// file: src/wechat/key/windows/key_extractor_v4.rs

use crate::errors::{Result, WeChatError};
// 确保这里的路径是正确的，指向您的 KeyExtractor trait 定义
use crate::wechat::key::{KeyExtractor, KeyVersion, WeChatKey};
use crate::wechat::process::WechatProcessInfo;
// 这是您确认存在的、真正的内存操作模块
use crate::utils::windows::memory;

use async_trait::async_trait;
use byteorder::{ByteOrder, LittleEndian};
use tokio::task;
use tracing::{debug, info};

// --- 常量定义 ---
const V4_KEY_PATTERN: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const POINTER_SIZE: usize = 8;
const KEY_SIZE: usize = 32;

#[derive(Clone)]
pub struct KeyExtractorV4 {}

impl KeyExtractorV4 {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// 内部实现的、自包含的指针验证函数
    fn is_valid_pointer(&self, ptr: u64, is_64bit: bool) -> bool {
        if is_64bit {
            // 检查指针是否在有效的64位用户空间地址范围内
            ptr > 0x10000 && ptr < 0x00007FFFFFFFFFFF
        } else {
            // 检查指针是否在有效的32位用户空间地址范围内
            ptr > 0x10000 && ptr < 0x7FFFFFFF
        }
    }

    /// 核心同步实现：在给定的内存块中进行反向搜索。
    fn _search_key_in_memory_impl(
        &self,
        process: &WechatProcessInfo,
        memory: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if memory.len() < V4_KEY_PATTERN.len() {
            return Ok(None);
        }

        // 使用 .rev() 实现从后向前的迭代搜索，对齐Go的LastIndex逻辑
        for pos in (0..=memory.len() - V4_KEY_PATTERN.len()).rev() {
            if &memory[pos..pos + V4_KEY_PATTERN.len()] == V4_KEY_PATTERN {
                if pos < POINTER_SIZE { continue; }

                let pointer_bytes_slice = &memory[(pos - POINTER_SIZE)..pos];
                let key_address = LittleEndian::read_u64(pointer_bytes_slice);

                // 调用内部实现的指针验证
                if !self.is_valid_pointer(key_address, process.is_64_bit) {
                    continue;
                }

                if let Ok(key_candidate) = memory::read_process_memory(process.pid, key_address as usize, KEY_SIZE) {
                    if self._validate_key_impl(&key_candidate) {
                        debug!("在内存块偏移 {} 处找到模式，其指针 {:#x} 指向有效密钥", pos, key_address);
                        return Ok(Some(key_candidate)); // 找到第一个就返回
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// 核心同步实现(验证逻辑)
    fn _validate_key_impl(&self, key: &[u8]) -> bool {
        key.len() == KEY_SIZE && !key.iter().all(|&b| b == 0)
    }

    /// 核心同步实现(总指挥)
    fn _extract_key_impl(&self, process: &WechatProcessInfo) -> Result<WeChatKey> {
        tracing::info!("开始对PID {} 进行同步内存扫描...", process.pid);
        
        let start_address: usize = 0x10000;
        let end_address: usize = if process.is_64_bit { 0x7FFFFFFFFFFF } else { 0x7FFFFFFF };
        
        // 搜索所有可能的模式位置
        let candidate_locations = memory::search_memory_for_pattern(
            process.pid, V4_KEY_PATTERN, start_address, end_address, 10
        )?;
        
        tracing::info!("在整个进程空间找到 {} 个V4密钥模式的候选位置", candidate_locations.len());
        for &loc in candidate_locations.iter().rev() {
            let pointer_address = loc - POINTER_SIZE;
            if let Ok(pointer_bytes) = memory::read_process_memory(process.pid, pointer_address, POINTER_SIZE) {
                let key_address = LittleEndian::read_u64(&pointer_bytes);
                tracing::info!("验证密钥pointer_bytes:  {}", hex::encode(pointer_bytes));
                if let Ok(key_candidate) = memory::read_process_memory(process.pid, key_address as usize, KEY_SIZE) {
                    tracing::info!("验证密钥key_candidate:  {}", hex::encode(key_candidate));
                }

            }
        }
        // 从地址最大的候选位置开始尝试，模拟Go的反向逻辑
        // for &loc in candidate_locations.iter().rev() {
        //      tracing::info!("验证密钥{}", hex::encode(key_candidate));
        //     // if loc < POINTER_SIZE { continue; }
        //     let pointer_address = loc - POINTER_SIZE;

        //     if let Ok(pointer_bytes) = memory::read_process_memory(process.pid, pointer_address, POINTER_SIZE) {
        //         let key_address = LittleEndian::read_u64(&pointer_bytes);

        //         // 调用内部实现的指针验证
        //         if self.is_valid_pointer(key_address, process.is_64_bit) {
        //             if let Ok(key_candidate) = memory::read_process_memory(process.pid, key_address as usize, KEY_SIZE) {
        //                 tracing::info!("验证密钥{}", hex::encode(key_candidate));
        //                 // if self._validate_key_impl(&key_candidate) {
        //                     // tracing::info!("在地址 {:#x} 的指针结构处成功找到并验证了密钥!", pointer_address);
        //                     // let key = WeChatKey::new(key_candidate, process.pid, KeyVersion::V40);
        //                     // return Ok(key);
        //                 // }
        //             }
        //         }
        //         let key = WeChatKey::new(vec![], process.pid, KeyVersion::V40);
        //         return Ok(key);
        //     }
        // }

        Err(WeChatError::KeyExtractionFailed("V4算法未找到有效密钥".to_string()).into())
    }
}

#[async_trait]
// 为 KeyExtractorV4 实现您定义的 KeyExtractor trait
impl KeyExtractor for KeyExtractorV4 {
    async fn extract_key(&self, process: &WechatProcessInfo) -> Result<WeChatKey> {
        let self_clone = self.clone();
        let process_clone = process.clone(); // 假设 WechatProcessInfo 实现了 Clone
        task::spawn_blocking(move || self_clone._extract_key_impl(&process_clone)).await?
    }

    async fn search_key_in_memory(&self, memory: &[u8], process: &WechatProcessInfo) -> Result<Option<Vec<u8>>> {
        let self_clone = self.clone();
        let memory_vec = memory.to_vec();
        let process_clone = process.clone();
        task::spawn_blocking(move || self_clone._search_key_in_memory_impl(&process_clone, &memory_vec)).await?
    }
    
    async fn validate_key(&self, key: &[u8]) -> Result<bool> {
        Ok(self._validate_key_impl(key))
    }
    
    fn supported_version(&self) -> KeyVersion {
        KeyVersion::V40
    }
}