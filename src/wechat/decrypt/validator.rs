//! 密钥验证器

use std::path::Path;
use tracing::{debug, info};

use crate::errors::Result;
use super::{DecryptVersion, Decryptor, v4::V4Decryptor};

/// 密钥验证器
pub struct KeyValidator {
    v4_decryptor: V4Decryptor,
}

impl KeyValidator {
    /// 创建新的密钥验证器
    pub fn new() -> Self {
        Self {
            v4_decryptor: V4Decryptor::new(),
        }
    }
    
    /// 自动检测版本并验证密钥
    /// 
    /// # 参数
    /// - `db_path`: 数据库文件路径
    /// - `key`: 待验证的密钥
    /// 
    /// # 返回
    /// - `Ok(Some(version))`: 密钥有效，返回对应版本
    /// - `Ok(None)`: 密钥无效
    /// - `Err(...)`: 验证过程出错
    pub async fn validate_key_auto(
        &self,
        db_path: &Path,
        key: &[u8],
    ) -> Result<Option<DecryptVersion>> {
        info!("开始自动密钥验证: {:?}", db_path);
        
        // 尝试V4版本
        debug!("尝试V4版本验证");
        if self.v4_decryptor.validate_key(db_path, key).await? {
            info!("密钥验证成功: V4版本");
            return Ok(Some(DecryptVersion::V4));
        }
        
        info!("密钥验证失败: 所有版本都不匹配");
        Ok(None)
    }
    
    /// 验证V4版本密钥
    pub async fn validate_v4_key(&self, db_path: &Path, key: &[u8]) -> Result<bool> {
        self.v4_decryptor.validate_key(db_path, key).await
    }
}

impl Default for KeyValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_key_validator_creation() {
        let validator = KeyValidator::new();
        // 基本创建测试
        assert!(true); // 如果能创建就说明没问题
    }
    
    #[tokio::test]
    async fn test_validate_key_auto_with_decrypted_file() {
        let validator = KeyValidator::new();
        
        // 创建一个临时文件，内容为SQLite头（已解密）
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"SQLite format 3\x00").unwrap();
        temp_file.flush().unwrap();
        
        let key = vec![0u8; 32];
        let result = validator.validate_key_auto(temp_file.path(), &key).await;
        
        // 应该返回None，因为文件已经解密
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
    
   
    #[tokio::test]
    async fn test_validate_v4_key() {
        let validator = KeyValidator::new();
        
        // 创建一个临时文件，内容为SQLite头（已解密）
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"SQLite format 3\x00").unwrap();
        temp_file.flush().unwrap();
        
        let key = vec![0u8; 32];
        let result = validator.validate_v4_key(temp_file.path(), &key).await;
        
        // 应该返回false，因为文件已经解密
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}