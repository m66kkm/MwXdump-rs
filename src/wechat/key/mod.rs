//! 微信密钥提取模块
//!
//! 该模块负责从微信进程内存中提取数据库解密密钥

use crate::errors::Result;
use crate::wechat::process::WechatProcessInfo;
use crate::wechat::WeChatVersion;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// 密钥数据结构
#[derive(Clone, Serialize, Deserialize)]
pub struct WeChatKey {
    /// 32字节的AES密钥
    pub key_data: Vec<u8>,
    /// 密钥来源进程PID
    pub source_pid: u32,
    /// 密钥提取时间
    pub extracted_at: chrono::DateTime<chrono::Utc>,
    /// 密钥版本信息
    pub version: KeyVersion,
}

/// 密钥版本枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyVersion {
    /// 微信3.x版本密钥
    V3x,
    /// 微信4.0版本密钥
    V40,
}

/// 密钥提取器接口
#[async_trait]
pub trait KeyExtractor: Send + Sync {
    /// 从指定进程中提取密钥
    async fn extract_key(&self, process: &WechatProcessInfo) -> Result<WeChatKey>;

    /// 在内存数据中搜索密钥
    async fn search_key_in_memory(&self, memory: &[u8]) -> Result<Option<Vec<u8>>>;

    /// 验证密钥是否有效
    async fn validate_key(&self, key: &[u8]) -> Result<bool>;

    /// 获取支持的密钥版本
    fn supported_version(&self) -> KeyVersion;
}

/// 密钥验证器接口
#[async_trait]
pub trait KeyValidator: Send + Sync {
    /// 验证密钥是否能够解密数据库
    async fn validate(&self, key: &[u8]) -> bool;

    /// 设置用于验证的数据库路径
    fn set_database_path(&mut self, path: &str);
}

/// 平台特定的密钥提取器
#[cfg(target_os = "windows")]
pub type PlatformKeyExtractor = windows::WindowsKeyExtractor;

#[cfg(target_os = "macos")]
pub type PlatformKeyExtractor = macos::MacOSKeyExtractor;

/// 创建平台特定的密钥提取器
pub fn create_key_extractor(version: KeyVersion) -> Result<PlatformKeyExtractor> {
    PlatformKeyExtractor::new(version)
}

impl WeChatKey {
    /// 创建新的密钥实例
    pub fn new(key_data: Vec<u8>, source_pid: u32, version: KeyVersion) -> Self {
        Self {
            key_data,
            source_pid,
            extracted_at: chrono::Utc::now(),
            version,
        }
    }

    /// 获取密钥的十六进制表示
    pub fn to_hex(&self) -> String {
        hex::encode(&self.key_data)
    }

    /// 从十六进制字符串创建密钥
    pub fn from_hex(hex_str: &str, source_pid: u32, version: KeyVersion) -> Result<Self> {
        let key_data = hex::decode(hex_str).map_err(|_| {
            crate::errors::WeChatError::KeyExtractionFailed("无效的十六进制密钥".to_string())
        })?;

        if key_data.len() != 32 {
            return Err(crate::errors::WeChatError::KeyExtractionFailed(
                "密钥长度必须为32字节".to_string(),
            )
            .into());
        }

        Ok(Self::new(key_data, source_pid, version))
    }

    /// 检查密钥是否有效（非全零）
    pub fn is_valid(&self) -> bool {
        !self.key_data.iter().all(|&b| b == 0) && self.key_data.len() == 32
    }
}

impl fmt::Debug for WeChatKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WeChatKey")
            .field("key_data", &format!("{}...(隐藏)", &self.to_hex()[..8]))
            .field("source_pid", &self.source_pid)
            .field("extracted_at", &self.extracted_at)
            .field("version", &self.version)
            .finish()
    }
}

impl fmt::Display for WeChatKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WeChatKey(版本: {:?}, PID: {}, 时间: {})",
            self.version,
            self.source_pid,
            self.extracted_at.format("%Y-%m-%d %H:%M:%S")
        )
    }
}

impl KeyVersion {
    /// 从进程信息推断密钥版本
    pub fn from_process(process: &WechatProcessInfo) -> Self {
        use tracing::{info, warn};

        info!(
            "开始为进程 {} (PID: {}) 推断密钥版本",
            process.name, process.pid
        );
        info!(
            "分析进程版本: 进程名={}, 版本={:?}, 路径={:?}",
            process.name, process.version, process.path
        );

        match &process.version {
            WeChatVersion::V3x { exact } => {
                info!("检测到V3x版本: {}", exact);
                // 验证版本号格式
                if exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.') {
                    KeyVersion::V3x
                } else {
                    warn!("V3x版本号格式无效: {}", exact);
                    KeyVersion::V3x
                }
            }
            WeChatVersion::V4x { exact } => {
                info!("检测到V4.0版本: {}", exact);
                // 验证版本号格式
                if exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.') {
                    KeyVersion::V40
                } else {
                    warn!("V4.0版本号格式无效: {}", exact);
                    KeyVersion::V40
                }
            }
            WeChatVersion::V3xW { exact } => {
                info!("检测到V3x版本: {}", exact);
                // 验证版本号格式
                if exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.') {
                    KeyVersion::V3x
                } else {
                    warn!("V3x版本号格式无效: {}", exact);
                    KeyVersion::V3x
                }
            }
            WeChatVersion::V4xW { exact } => {
                info!("检测到V4.0版本: {}", exact);
                // 验证版本号格式
                if exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.') {
                    KeyVersion::V40
                } else {
                    warn!("V4.0版本号格式无效: {}", exact);
                    KeyVersion::V40
                }
            }
            WeChatVersion::Unknown => {
                // 对于WeChat.exe，如果版本未知，默认推断为V3x
                // 因为大多数WeChat.exe是V3版本
                info!("WeChat.exe版本未知，默认推断为V3x版本");
                KeyVersion::V3x
            }
        }
    }

    /// 获取版本的字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyVersion::V3x => "3.x",
            KeyVersion::V40 => "4.0",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wechat_key_creation() {
        let key_data = vec![0x01; 32];
        let key = WeChatKey::new(key_data.clone(), 1234, KeyVersion::V3x);

        assert_eq!(key.key_data, key_data);
        assert_eq!(key.source_pid, 1234);
        assert_eq!(key.version, KeyVersion::V3x);
        assert!(key.is_valid());
    }

    #[test]
    fn test_key_hex_conversion() {
        let hex_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = WeChatKey::from_hex(hex_str, 1234, KeyVersion::V3x).unwrap();

        assert_eq!(key.to_hex(), hex_str);
        assert!(key.is_valid());
    }

    #[test]
    fn test_invalid_key() {
        let key_data = vec![0x00; 32]; // 全零密钥
        let key = WeChatKey::new(key_data, 1234, KeyVersion::V3x);

        assert!(!key.is_valid());
    }

    #[test]
    fn test_key_version_from_str() {
        assert_eq!(KeyVersion::V3x.as_str(), "3.x");
        assert_eq!(KeyVersion::V40.as_str(), "4.0");
    }
}
