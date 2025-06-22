/// 密钥数据结构
/// 
use super::KeyVersion;
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use std::fmt;
use crate::errors::Result;

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



/// 密钥验证器接口
#[async_trait]
pub trait KeyValidator: Send + Sync {
    /// 验证密钥是否能够解密数据库
    async fn validate(&self, key: &[u8]) -> bool;

    /// 设置用于验证的数据库路径
    fn set_database_path(&mut self, path: &str);
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
