
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use crate::wechat::process::WechatProcessInfo;
use crate::errors::Result;
use super::WeChatKey;
use super::KeyVersion;

/// 平台特定的密钥提取器
#[cfg(target_os = "windows")]
pub type PlatformKeyExtractor = super::windows::KeyExtractor;

#[cfg(target_os = "macos")]
pub type PlatformKeyExtractor = macos::MacOSKeyExtractor;

/// 密钥提取器接口
#[async_trait]
pub trait KeyExtractor: Send + Sync {
    /// 从指定进程中提取密钥
    async fn extract_key(&self, process: &WechatProcessInfo) -> Result<WeChatKey>;

    /// 在内存数据中搜索密钥
    async fn search_key_in_memory(&self, memory: &[u8], process: &WechatProcessInfo) -> Result<Option<Vec<u8>>>;

    /// 验证密钥是否有效
    async fn validate_key(&self, key: &[u8]) -> Result<bool>;

    /// 获取支持的密钥版本
    fn supported_version(&self) -> KeyVersion;
}

/// 创建平台特定的密钥提取器
pub fn create_key_extractor() -> Result<PlatformKeyExtractor> {
    PlatformKeyExtractor::new()
}

