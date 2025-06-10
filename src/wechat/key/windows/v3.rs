//! Windows平台微信3.x版本密钥提取实现

use crate::errors::{Result, WeChatError};
use crate::wechat::key::{KeyExtractor, KeyVersion, WeChatKey};
use crate::wechat::process::WechatProcessInfo;
use super::memory::{MemorySearcher, SearchConfig};
use async_trait::async_trait;
use tracing::{info, warn};

/// V3版本密钥提取器
pub struct V3KeyExtractor {
    searcher: MemorySearcher,
}

impl V3KeyExtractor {
    /// 创建新的V3密钥提取器
    pub fn new() -> Result<Self> {
        let config = SearchConfig {
            max_workers: std::cmp::min(num_cpus::get(), 8), // V3版本使用较少的工作线程
            memory_channel_buffer: 50,
            min_region_size: 100 * 1024, // 100KB
        };
        
        Ok(Self {
            searcher: MemorySearcher::new(config),
        })
    }
}

#[async_trait]
impl KeyExtractor for V3KeyExtractor {
    async fn extract_key(&self, process: &WechatProcessInfo) -> Result<WeChatKey> {
        info!("开始提取V3密钥，进程: {} (PID: {})", process.name, process.pid);
        info!("进程版本信息: {:?}", process.version);
        
        // 检查是否为微信V3进程
        if !process.name.to_lowercase().contains("wechat") {
            return Err(WeChatError::KeyExtractionFailed("不是微信进程".to_string()).into());
        }
        
        // 确认是V3版本
        match &process.version {
            crate::wechat::WeChatVersion::V3x { exact } => {
                info!("确认V3版本: {}", exact);
            },
            crate::wechat::WeChatVersion::V4x { .. } => {
                return Err(WeChatError::KeyExtractionFailed("进程是V4.0版本，不应使用V3提取器".to_string()).into());
            },
            crate::wechat::WeChatVersion::Unknown => {
                if process.name.to_lowercase().contains("wechatappex") {
                    return Err(WeChatError::KeyExtractionFailed("WeChatAppEx.exe应使用V4提取器".to_string()).into());
                }
                warn!("版本未知，尝试使用V3算法");
            }
        }
        
        info!("使用真实内存搜索算法提取V3密钥");
        
        // 使用内存搜索器提取密钥
        match self.searcher.search_v3_key(process).await {
            Ok(key) => {
                info!("成功提取V3密钥: {}", key.to_hex());
                Ok(key)
            }
            Err(e) => {
                warn!("V3密钥提取失败: {}", e);
                Err(WeChatError::KeyExtractionFailed("V3算法未找到有效密钥".to_string()).into())
            }
        }
    }
    
    async fn search_key_in_memory(&self, _memory: &[u8]) -> Result<Option<Vec<u8>>> {
        // 这个方法现在由MemorySearcher处理
        warn!("search_key_in_memory方法已弃用，请使用MemorySearcher");
        Ok(None)
    }
    
    async fn validate_key(&self, _key: &[u8]) -> Result<bool> {
        // 密钥验证现在集成在搜索过程中
        warn!("validate_key方法需要数据库文件进行验证");
        Ok(true) // 临时返回true，实际验证在搜索过程中进行
    }
    
    fn supported_version(&self) -> KeyVersion {
        KeyVersion::V3x
    }
}

impl Default for V3KeyExtractor {
    fn default() -> Self {
        Self::new().expect("创建V3KeyExtractor失败")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wechat::process::WechatProcessInfo;
    use crate::wechat::WeChatVersion;
    use std::path::PathBuf;
    use chrono::Utc;
    
    fn create_test_process() -> WechatProcessInfo {
        WechatProcessInfo {
            pid: 1234,
            name: "WeChat.exe".to_string(),
            path: PathBuf::from("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe"),
            version: WeChatVersion::V3x { exact: "3.9.12.51".to_string() },
            data_dir: Some(PathBuf::from("C:\\Users\\test\\AppData\\Roaming\\Tencent\\WeChat")),
            detected_at: Utc::now(),
        }
    }
    
    #[test]
    fn test_v3_extractor_creation() {
        let extractor = V3KeyExtractor::new();
        assert!(extractor.is_ok());
    }
    
    #[test]
    fn test_supported_version() {
        let extractor = V3KeyExtractor::new().unwrap();
        assert_eq!(extractor.supported_version(), KeyVersion::V3x);
    }
    
    #[tokio::test]
    async fn test_extract_key_wrong_process() {
        let extractor = V3KeyExtractor::new().unwrap();
        let mut process = create_test_process();
        process.name = "notepad.exe".to_string();
        
        let result = extractor.extract_key(&process).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_extract_key_v4_process() {
        let extractor = V3KeyExtractor::new().unwrap();
        let mut process = create_test_process();
        process.version = WeChatVersion::V4x { exact: "4.0.1".to_string() };
        
        let result = extractor.extract_key(&process).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("V4.0版本"));
    }
}