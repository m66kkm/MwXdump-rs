//! 密钥验证器实现

use crate::wechat::key::KeyValidator;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::{debug, warn};

/// 数据库密钥验证器
pub struct DatabaseValidator {
    /// 用于验证的数据库路径
    database_path: Option<PathBuf>,
}

impl DatabaseValidator {
    /// 创建新的数据库验证器
    pub fn new() -> Self {
        Self {
            database_path: None,
        }
    }
    
    /// 尝试使用密钥解密数据库头部
    async fn try_decrypt_header(&self, key: &[u8]) -> bool {
        if let Some(db_path) = &self.database_path {
            // 读取数据库文件头部
            match tokio::fs::read(db_path).await {
                Ok(data) => {
                    if data.len() < 1024 {
                        warn!("数据库文件太小: {:?}", db_path);
                        return false;
                    }
                    
                    // 尝试解密前1024字节
                    self.decrypt_and_validate(&data[..1024], key).await
                }
                Err(e) => {
                    warn!("无法读取数据库文件 {:?}: {}", db_path, e);
                    false
                }
            }
        } else {
            // 没有数据库路径时，只做基本验证
            self.basic_key_validation(key)
        }
    }
    
    /// 使用AES解密并验证
    async fn decrypt_and_validate(&self, data: &[u8], key: &[u8]) -> bool {
        use aes::Aes256;
        use aes::cipher::{BlockDecrypt, KeyInit};
        use aes::cipher::generic_array::GenericArray;
        
        if key.len() != 32 {
            return false;
        }
        
        // 创建AES解密器
        let cipher = match Aes256::new_from_slice(key) {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        // 尝试解密第一个块（16字节）
        if data.len() < 16 {
            return false;
        }
        
        let mut block = GenericArray::clone_from_slice(&data[..16]);
        cipher.decrypt_block(&mut block);
        
        // 检查解密后的数据是否包含SQLite头部标识
        let decrypted = block.as_slice();
        
        // SQLite数据库文件头部应该以"SQLite format 3"开始
        let sqlite_header = b"SQLite format 3";
        if decrypted.len() >= sqlite_header.len() {
            let matches = decrypted[..sqlite_header.len()] == *sqlite_header;
            debug!("SQLite头部匹配: {}", matches);
            matches
        } else {
            false
        }
    }
    
    /// 基本密钥验证
    fn basic_key_validation(&self, key: &[u8]) -> bool {
        // 检查密钥长度
        if key.len() != 32 {
            return false;
        }
        
        // 检查密钥不是全零
        if key.iter().all(|&b| b == 0) {
            return false;
        }
        
        // 检查密钥不是全0xFF
        if key.iter().all(|&b| b == 0xFF) {
            return false;
        }
        
        // 检查密钥有足够的熵（简单检查）
        let mut byte_counts = [0u32; 256];
        for &byte in key {
            byte_counts[byte as usize] += 1;
        }
        
        // 如果某个字节出现次数过多，可能不是有效密钥
        let max_count = byte_counts.iter().max().unwrap_or(&0);
        if *max_count > 8 {  // 32字节中某个字节出现超过8次
            return false;
        }
        
        true
    }
}

impl Default for DatabaseValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyValidator for DatabaseValidator {
    async fn validate(&self, key: &[u8]) -> bool {
        debug!("验证密钥，长度: {} 字节", key.len());
        
        // 首先进行基本验证
        if !self.basic_key_validation(key) {
            debug!("基本验证失败");
            return false;
        }
        
        // 如果有数据库路径，尝试解密验证
        self.try_decrypt_header(key).await
    }
    
    fn set_database_path(&mut self, path: &str) {
        self.database_path = Some(PathBuf::from(path));
        debug!("设置数据库路径: {}", path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_basic_key_validation() {
        let validator = DatabaseValidator::new();
        
        // 有效密钥
        let valid_key = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert!(validator.basic_key_validation(&valid_key));
        
        // 无效密钥（全零）
        let zero_key = vec![0x00; 32];
        assert!(!validator.basic_key_validation(&zero_key));
        
        // 无效密钥（全0xFF）
        let ff_key = vec![0xFF; 32];
        assert!(!validator.basic_key_validation(&ff_key));
        
        // 无效密钥（长度错误）
        let short_key = vec![0x01; 16];
        assert!(!validator.basic_key_validation(&short_key));
        
        // 无效密钥（熵太低）
        let low_entropy_key = vec![0x01; 32];
        assert!(!validator.basic_key_validation(&low_entropy_key));
    }
    
    #[tokio::test]
    async fn test_validator_without_database() {
        let validator = DatabaseValidator::new();
        
        let valid_key = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        
        assert!(validator.validate(&valid_key).await);
    }
    
    #[tokio::test]
    async fn test_set_database_path() {
        let mut validator = DatabaseValidator::new();
        validator.set_database_path("/path/to/database.db");
        
        assert!(validator.database_path.is_some());
        assert_eq!(validator.database_path.unwrap().to_str().unwrap(), "/path/to/database.db");
    }
}