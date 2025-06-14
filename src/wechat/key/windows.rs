//! Windows平台的微信密钥提取实现

use super::{KeyExtractor, KeyValidator, KeyVersion, WeChatKey};
use crate::errors::{Result, WeChatError};
use crate::wechat::process::WechatProcessInfo;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

#[cfg(target_os = "windows")]
pub mod memory;
#[cfg(target_os = "windows")]
pub mod key_extractor_v4;
#[cfg(target_os = "windows")]
pub mod validator;
#[cfg(target_os = "windows")]
pub mod winapi;

/// Windows平台的密钥提取器
pub struct WindowsKeyExtractor {
    version: KeyVersion,
    validator: Arc<Mutex<Option<Box<dyn KeyValidator>>>>,
}

impl WindowsKeyExtractor {
    /// 创建新的Windows密钥提取器
    pub fn new(version: KeyVersion) -> Result<Self> {
        Ok(Self {
            version,
            validator: Arc::new(Mutex::new(None)),
        })
    }

    /// 设置密钥验证器
    pub async fn set_validator(&self, validator: Box<dyn KeyValidator>) {
        let mut guard = self.validator.lock().await;
        *guard = Some(validator);
    }
}

#[async_trait]
impl KeyExtractor for WindowsKeyExtractor {
    async fn extract_key(&self, process: &WechatProcessInfo) -> Result<WeChatKey> {
        info!(
            "开始从进程 {} (PID: {}) 提取密钥",
            process.name, process.pid
        );

        // 检查进程是否仍在运行
        if !process.is_running().await {
            return Err(WeChatError::ProcessNotFound.into());
        }

        match self.version {
            KeyVersion::V3x => {
                Err(WeChatError::UnsupportedVersion {
                        version:  self.version.as_str().to_string(),
                }.into())
            }
            KeyVersion::V40 => {
                #[cfg(target_os = "windows")]
                {
                    let extractor = key_extractor_v4::KeyExtractorV4::new()?;
                    extractor.extract_key(process).await
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Err(WeChatError::UnsupportedVersion {
                        version: "V4.0 on non-Windows".to_string(),
                    }
                    .into())
                }
            }
        }
    }

    async fn search_key_in_memory(&self, memory: &[u8], process: &WechatProcessInfo) -> Result<Option<Vec<u8>>> {
        match self.version {
            KeyVersion::V3x => Ok(None),
            KeyVersion::V40 => {
                #[cfg(target_os = "windows")]
                {
                    let extractor = key_extractor_v4::KeyExtractorV4::new()?;
                    extractor.search_key_in_memory(memory, process).await
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Ok(None)
                }
            }
        }
    }

    async fn validate_key(&self, key: &[u8]) -> Result<bool> {
        let validator_guard = self.validator.lock().await;
        if let Some(validator) = validator_guard.as_ref() {
            Ok(validator.validate(key).await)
        } else {
            // 没有验证器时，只做基本检查
            Ok(key.len() == 32 && !key.iter().all(|&b| b == 0))
        }
    }

    fn supported_version(&self) -> KeyVersion {
        self.version.clone()
    }
}

/// 内存搜索的通用工具函数
pub(crate) mod memory_utils {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// 在内存中搜索模式
    pub fn find_pattern(memory: &[u8], pattern: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        let pattern_len = pattern.len();

        if pattern_len == 0 || pattern_len > memory.len() {
            return positions;
        }

        for i in 0..=(memory.len() - pattern_len) {
            if memory[i..i + pattern_len] == *pattern {
                positions.push(i);
            }
        }

        positions
    }

    /// 在内存中从后向前搜索模式
    pub fn find_pattern_reverse(memory: &[u8], pattern: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        let pattern_len = pattern.len();

        if pattern_len == 0 || pattern_len > memory.len() {
            return positions;
        }

        let mut i = memory.len() - pattern_len;
        loop {
            if memory[i..i + pattern_len] == *pattern {
                positions.push(i);
            }

            if i == 0 {
                break;
            }
            i -= 1;
        }

        positions
    }

    /// 可取消的内存搜索
    pub fn find_pattern_cancellable(
        memory: &[u8],
        pattern: &[u8],
        cancel_flag: Arc<AtomicBool>,
    ) -> Vec<usize> {
        let mut positions = Vec::new();
        let pattern_len = pattern.len();

        if pattern_len == 0 || pattern_len > memory.len() {
            return positions;
        }

        for i in (0..=(memory.len() - pattern_len)).step_by(1024) {
            // 每1024字节检查一次取消标志
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }

            let end = std::cmp::min(i + 1024, memory.len() - pattern_len + 1);
            for j in i..end {
                if memory[j..j + pattern_len] == *pattern {
                    positions.push(j);
                }
            }
        }

        positions
    }

    /// 验证指针值是否在合理范围内
    pub fn is_valid_pointer(ptr: u64, is_64bit: bool) -> bool {
        if is_64bit {
            ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF
        } else {
            ptr > 0x10000 && ptr < 0x7FFFFFFF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory_utils::*;
    use super::*;

    #[test]
    fn test_find_pattern() {
        let memory = b"hello world hello rust";
        let pattern = b"hello";
        let positions = find_pattern(memory, pattern);

        assert_eq!(positions, vec![0, 12]);
    }

    #[test]
    fn test_find_pattern_reverse() {
        let memory = b"hello world hello rust";
        let pattern = b"hello";
        let positions = find_pattern_reverse(memory, pattern);

        assert_eq!(positions, vec![12, 0]);
    }

    #[test]
    fn test_is_valid_pointer() {
        // 64位指针测试
        assert!(is_valid_pointer(0x12345678, true));
        assert!(!is_valid_pointer(0x1000, true));
        assert!(!is_valid_pointer(0x800000000000, true));

        // 32位指针测试
        assert!(is_valid_pointer(0x12345678, false));
        assert!(!is_valid_pointer(0x1000, false));
        assert!(!is_valid_pointer(0x80000000, false));
    }

    #[tokio::test]
    async fn test_windows_key_extractor_creation() {
        let extractor = WindowsKeyExtractor::new(KeyVersion::V3x);
        assert!(extractor.is_ok());

        let extractor = extractor.unwrap();
        assert_eq!(extractor.supported_version(), KeyVersion::V3x);
    }
}
