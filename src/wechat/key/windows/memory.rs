//! 内存搜索和密钥提取模块
//! 
//! 实现在进程内存中搜索微信密钥的核心算法

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use crate::errors::{Result, WeChatError};
use crate::wechat::process::WechatProcessInfo;
use crate::wechat::key::{WeChatKey, KeyVersion};
use super::winapi::{WindowsApi, MemoryInfo};

/// 内存搜索配置
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// 最大工作线程数
    pub max_workers: usize,
    /// 内存通道缓冲区大小
    pub memory_channel_buffer: usize,
    /// 最小内存区域大小（字节）
    pub min_region_size: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_workers: std::cmp::min(num_cpus::get(), 16),
            memory_channel_buffer: 100,
            min_region_size: 100 * 1024, // 100KB
        }
    }
}

/// 内存搜索器
pub struct MemorySearcher {
    config: SearchConfig,
}

impl MemorySearcher {
    /// 创建新的内存搜索器
    pub fn new(config: SearchConfig) -> Self {
        Self { config }
    }
    
    /// 并发搜索密钥
    async fn concurrent_search(
        &self,
        api: WindowsApi,
        regions: Vec<MemoryInfo>,
        is_64bit: bool,
        source_pid: u32,
    ) -> Result<WeChatKey> {
        let api = Arc::new(api);
        let (memory_tx, memory_rx) = mpsc::channel(self.config.memory_channel_buffer);
        let memory_rx = Arc::new(tokio::sync::Mutex::new(memory_rx));
        let (result_tx, result_rx) = oneshot::channel();
        let result_tx = Arc::new(tokio::sync::Mutex::new(Some(result_tx)));
        
        // 启动内存读取任务
        let api_clone = api.clone();
        let memory_producer = tokio::spawn(async move {
            for region in regions {
                debug!("读取内存区域: 0x{:X} - 0x{:X}",
                       region.base_address,
                       region.base_address + region.region_size);
                
                match api_clone.read_memory(region.base_address, region.region_size) {
                    Ok(memory_data) => {
                        if memory_tx.send((region.base_address, memory_data)).await.is_err() {
                            break; // 接收端已关闭
                        }
                    }
                    Err(e) => {
                        warn!("读取内存区域失败: 0x{:X}, 错误: {}", region.base_address, e);
                    }
                }
            }
        });
        
        // 启动工作线程
        let mut workers = JoinSet::new();
        for worker_id in 0..self.config.max_workers {
            let api_clone = api.clone();
            let result_tx_clone = result_tx.clone();
            let memory_rx_clone = memory_rx.clone();
            
            workers.spawn(async move {
                Self::search_worker(
                    worker_id,
                    api_clone,
                    memory_rx_clone,
                    is_64bit,
                    source_pid,
                    result_tx_clone,
                ).await;
            });
        }
        
        // 等待结果
        match result_rx.await {
            Ok(key) => {
                // 找到密钥，取消所有任务
                memory_producer.abort();
                workers.abort_all();
                Ok(key)
            }
            Err(_) => {
                // 等待所有任务完成
                let _ = memory_producer.await;
                while workers.join_next().await.is_some() {}
                Err(WeChatError::KeyExtractionFailed("未找到有效密钥".to_string()).into())
            }
        }
    }
    
    /// 搜索工作线程
    async fn search_worker(
        worker_id: usize,
        api: Arc<WindowsApi>,
        memory_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(usize, Vec<u8>)>>>,
        is_64bit: bool,
        source_pid: u32,
        result_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<WeChatKey>>>>,
    ) {
        debug!("启动搜索工作线程 {}", worker_id);
        
        // 定义搜索模式
        let key_pattern = if is_64bit {
            vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        } else {
            vec![0x20, 0x00, 0x00, 0x00]
        };
        
        let ptr_size = if is_64bit { 8 } else { 4 };
        
        loop {
            let memory_data = {
                let mut rx = memory_rx.lock().await;
                match rx.recv().await {
                    Some(data) => data,
                    None => break, // 通道已关闭
                }
            };
            
            let (base_address, memory_data) = memory_data;
            debug!("工作线程 {} 处理内存块: 0x{:X}, 大小: {} KB", 
                   worker_id, base_address, memory_data.len() / 1024);
            
            // 在内存中搜索模式
            let mut search_pos = memory_data.len();
            
            loop {
                // 从后往前搜索模式
                if let Some(pattern_pos) = Self::find_pattern_reverse(&memory_data[..search_pos], &key_pattern) {
                    if pattern_pos < ptr_size {
                        break; // 没有足够空间读取指针
                    }
                    
                    // 读取指针值
                    let ptr_start = pattern_pos - ptr_size;
                    let ptr_value = if is_64bit {
                        u64::from_le_bytes([
                            memory_data[ptr_start], memory_data[ptr_start + 1],
                            memory_data[ptr_start + 2], memory_data[ptr_start + 3],
                            memory_data[ptr_start + 4], memory_data[ptr_start + 5],
                            memory_data[ptr_start + 6], memory_data[ptr_start + 7],
                        ])
                    } else {
                        u32::from_le_bytes([
                            memory_data[ptr_start], memory_data[ptr_start + 1],
                            memory_data[ptr_start + 2], memory_data[ptr_start + 3],
                        ]) as u64
                    };
                    
                    // 验证指针值的合理性
                    if ptr_value > 0x10000 && ptr_value < 0x7FFFFFFFFFFF {
                        debug!("工作线程 {} 找到候选指针: 0x{:X}", worker_id, ptr_value);
                        
                        // 尝试读取密钥数据
                        if let Ok(key_data) = api.read_memory(ptr_value as usize, 32) {
                            // 这里应该验证密钥，但目前先返回找到的密钥
                            let key = WeChatKey::new(key_data, source_pid, KeyVersion::V3x);
                            
                            info!("工作线程 {} 找到潜在密钥: {}", worker_id, key.to_hex());
                            
                            // 尝试发送结果
                            if let Ok(mut sender) = result_tx.try_lock() {
                                if let Some(tx) = sender.take() {
                                    let _ = tx.send(key);
                                    return;
                                }
                            }
                        }
                    }
                    
                    search_pos = pattern_pos;
                } else {
                    break; // 没有找到更多模式
                }
            }
        }
        
        debug!("工作线程 {} 完成", worker_id);
    }
    
    /// 从后往前搜索模式
    fn find_pattern_reverse(data: &[u8], pattern: &[u8]) -> Option<usize> {
        if pattern.is_empty() || data.len() < pattern.len() {
            return None;
        }
        
        for i in (0..=data.len() - pattern.len()).rev() {
            if data[i..i + pattern.len()] == *pattern {
                return Some(i);
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_find_pattern_reverse() {
        let data = vec![0x01, 0x02, 0x20, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00, 0x00];
        let pattern = vec![0x20, 0x00, 0x00, 0x00];
        
        // 应该找到最后一个匹配位置
        assert_eq!(MemorySearcher::find_pattern_reverse(&data, &pattern), Some(7));
    }
    
    #[test]
    fn test_find_pattern_reverse_not_found() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let pattern = vec![0x20, 0x00, 0x00, 0x00];
        
        assert_eq!(MemorySearcher::find_pattern_reverse(&data, &pattern), None);
    }
    
    #[test]
    fn test_search_config_default() {
        let config = SearchConfig::default();
        assert!(config.max_workers > 0);
        assert!(config.memory_channel_buffer > 0);
        assert_eq!(config.min_region_size, 100 * 1024);
    }
}