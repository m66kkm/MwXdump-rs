//! 微信数据库解密模块
//! 
//! 支持微信V3和V4版本的SQLite数据库解密

use async_trait::async_trait;
use std::path::Path;
use crate::errors::Result;

pub mod common;
pub mod v4;
pub mod validator;

/// 解密器版本
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptVersion {
    /// 微信4.0版本
    V4,
}

impl DecryptVersion {
    /// 获取版本字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            DecryptVersion::V4 => "V4",
        }
    }
}

/// 解密器配置
#[derive(Debug, Clone)]
pub struct DecryptConfig {
    /// 版本
    pub version: DecryptVersion,
    /// 页面大小
    pub page_size: usize,
    /// PBKDF2迭代次数
    pub iter_count: u32,
    /// HMAC大小
    pub hmac_size: usize,
    /// 保留区域大小
    pub reserve_size: usize,
}

impl DecryptConfig {
    /// 创建V4配置
    pub fn v4() -> Self {
        Self {
            version: DecryptVersion::V4,
            page_size: 4096,
            iter_count: 256000,
            hmac_size: 64,
            reserve_size: 80, // IV(16) + HMAC(64) = 80
        }
    }
}

/// 解密进度回调
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

/// 解密器trait
#[async_trait]
pub trait Decryptor: Send + Sync {
    /// 解密数据库
    /// 
    /// # 参数
    /// - `input_path`: 加密的数据库文件路径
    /// - `output_path`: 解密后的数据库文件路径
    /// - `key`: 32字节的解密密钥
    /// 
    /// # 返回
    /// - `Ok(())`: 解密成功
    /// - `Err(...)`: 解密失败
    async fn decrypt_database(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
    ) -> Result<()>;
    
    /// 解密数据库（带进度回调）
    async fn decrypt_database_with_progress(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()>;
    
    /// 验证密钥是否正确
    /// 
    /// # 参数
    /// - `db_path`: 数据库文件路径
    /// - `key`: 待验证的密钥
    /// 
    /// # 返回
    /// - `Ok(true)`: 密钥正确
    /// - `Ok(false)`: 密钥错误
    /// - `Err(...)`: 验证过程出错
    async fn validate_key(
        &self,
        db_path: &Path,
        key: &[u8],
    ) -> Result<bool>;
    
    /// 获取配置
    fn config(&self) -> &DecryptConfig;
    
    /// 获取版本
    fn version(&self) -> DecryptVersion {
        self.config().version
    }
}

/// 创建解密器
/// 
/// # 参数
/// - `version`: 解密器版本
/// 
/// # 返回
/// 对应版本的解密器实例
pub fn create_decryptor(version: DecryptVersion) -> Box<dyn Decryptor> {
    match version {
        DecryptVersion::V4 => Box::new(v4::V4Decryptor::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decrypt_version() {
        assert_eq!(DecryptVersion::V4.as_str(), "V4");
    }
    
    #[test]
    fn test_decrypt_config() {

        let v4_config = DecryptConfig::v4();
        assert_eq!(v4_config.version, DecryptVersion::V4);
        assert_eq!(v4_config.iter_count, 256000);
        assert_eq!(v4_config.hmac_size, 64);
    }
    
    #[test]
    fn test_create_decryptor() {

        let v4_decryptor = create_decryptor(DecryptVersion::V4);
        assert_eq!(v4_decryptor.version(), DecryptVersion::V4);
    }
}