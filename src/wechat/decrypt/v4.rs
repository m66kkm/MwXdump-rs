//! 微信V4版本解密器实现

use async_trait::async_trait;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::errors::{Result, WeChatError};
use super::{
    common::{
        derive_keys_v4, is_database_encrypted, decrypt_page, verify_page_hmac,
        SALT_SIZE, SQLITE_HEADER,
    },
    DecryptConfig, DecryptVersion, Decryptor, ProgressCallback,
};

/// V4版本解密器
pub struct V4Decryptor {
    config: DecryptConfig,
}

impl V4Decryptor {
    /// 创建新的V4解密器
    pub fn new() -> Self {
        Self {
            config: DecryptConfig::v4(),
        }
    }
    
    /// 读取数据库文件信息
    async fn read_db_info(&self, file_path: &Path) -> Result<(u64, Vec<u8>)> {
        let mut file = File::open(file_path).await
            .map_err(|e| WeChatError::DecryptionFailed(format!("打开文件失败: {}", e)))?;
        
        // 获取文件大小
        let file_size = file.metadata().await
            .map_err(|e| WeChatError::DecryptionFailed(format!("获取文件信息失败: {}", e)))?
            .len();
        
        // 读取第一页
        let mut first_page = vec![0u8; self.config.page_size];
        let bytes_read = file.read(&mut first_page).await
            .map_err(|e| WeChatError::DecryptionFailed(format!("读取第一页失败: {}", e)))?;
        
        if bytes_read < self.config.page_size {
            first_page.truncate(bytes_read);
        }
        
        Ok((file_size, first_page))
    }
    
    /// 解密数据库的核心实现
    async fn decrypt_database_impl(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        info!("开始V4数据库解密: {:?} -> {:?}", input_path, output_path);
        
        // 1. 读取数据库信息
        let (file_size, first_page) = self.read_db_info(input_path).await?;
        let total_pages = ((file_size as usize) + self.config.page_size - 1) / self.config.page_size;
        
        debug!("文件大小: {} 字节, 总页数: {}", file_size, total_pages);
        
        // 2. 检查是否已解密
        if !is_database_encrypted(&first_page) {
            return Err(WeChatError::DecryptionFailed("数据库已经解密".to_string()).into());
        }
        
        // 3. 提取Salt
        if first_page.len() < SALT_SIZE {
            return Err(WeChatError::DecryptionFailed("第一页数据不完整".to_string()).into());
        }
        
        let salt = &first_page[..SALT_SIZE];
        debug!("提取Salt: {} 字节", salt.len());
        
        // 4. 派生密钥
        let mut derived_keys = derive_keys_v4(key, salt)?;
        
        // 5. 验证密钥
        if !verify_page_hmac(&first_page, &derived_keys.mac_key, 0, &self.config)? {
            derived_keys.zeroize();
            return Err(WeChatError::DecryptionFailed("密钥验证失败".to_string()).into());
        }
        
        info!("密钥验证成功，开始解密");
        
        // 6. 打开输入输出文件
        let mut input_file = File::open(input_path).await
            .map_err(|e| WeChatError::DecryptionFailed(format!("打开输入文件失败: {}", e)))?;
        
        let mut output_file = File::create(output_path).await
            .map_err(|e| WeChatError::DecryptionFailed(format!("创建输出文件失败: {}", e)))?;
        
        // 7. 写入SQLite头
        output_file.write_all(SQLITE_HEADER).await
            .map_err(|e| WeChatError::DecryptionFailed(format!("写入SQLite头失败: {}", e)))?;
        
        // 8. 解密所有页面
        let mut processed_pages = 0u64;
        
        for page_num in 0..total_pages {
            // 读取页面数据
            let mut page_data = vec![0u8; self.config.page_size];
            let bytes_read = input_file.read(&mut page_data).await
                .map_err(|e| WeChatError::DecryptionFailed(format!("读取页面 {} 失败: {}", page_num, e)))?;
            
            if bytes_read == 0 {
                break;
            }
            
            // 处理最后一页
            if bytes_read < self.config.page_size {
                page_data.truncate(bytes_read);
                debug!("最后一页大小: {} 字节", bytes_read);
            }
            
            // 检查是否为空页面
            if page_data.iter().all(|&b| b == 0) {
                debug!("跳过空页面 {}", page_num);
                output_file.write_all(&page_data).await
                    .map_err(|e| WeChatError::DecryptionFailed(format!("写入空页面失败: {}", e)))?;
                processed_pages += 1;
                continue;
            }
            
            // 解密页面
            match decrypt_page(
                &page_data,
                &derived_keys.enc_key,
                &derived_keys.mac_key,
                page_num as u64,
                &self.config,
            ) {
                Ok(decrypted) => {
                    output_file.write_all(&decrypted).await
                        .map_err(|e| WeChatError::DecryptionFailed(format!("写入解密页面失败: {}", e)))?;
                    
                    processed_pages += 1;
                    
                    // 调用进度回调
                    if let Some(ref callback) = progress_callback {
                        callback(processed_pages, total_pages as u64);
                    }
                }
                Err(e) => {
                    warn!("页面 {} 解密失败: {}, 跳过", page_num, e);
                    // 写入原始数据作为备用
                    output_file.write_all(&page_data).await
                        .map_err(|e| WeChatError::DecryptionFailed(format!("写入原始页面失败: {}", e)))?;
                    processed_pages += 1;
                }
            }
        }
        
        // 9. 清理敏感数据
        derived_keys.zeroize();
        
        info!("V4数据库解密完成，处理了 {} 页", processed_pages);
        Ok(())
    }
}

impl Default for V4Decryptor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Decryptor for V4Decryptor {
    async fn decrypt_database(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
    ) -> Result<()> {
        self.decrypt_database_impl(input_path, output_path, key, None).await
    }
    
    async fn decrypt_database_with_progress(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        self.decrypt_database_impl(input_path, output_path, key, progress_callback).await
    }
    
    async fn validate_key(
        &self,
        db_path: &Path,
        key: &[u8],
    ) -> Result<bool> {
        debug!("验证V4密钥");
        
        // 读取第一页
        let (_, first_page) = self.read_db_info(db_path).await?;
        
        // 检查是否已解密
        if !is_database_encrypted(&first_page) {
            return Ok(false);
        }
        
        // 提取Salt
        if first_page.len() < SALT_SIZE {
            return Ok(false);
        }
        
        let salt = &first_page[..SALT_SIZE];
        
        // 派生密钥
        let mut derived_keys = match derive_keys_v4(key, salt) {
            Ok(keys) => keys,
            Err(_) => return Ok(false),
        };
        
        // 验证HMAC
        let result = verify_page_hmac(&first_page, &derived_keys.mac_key, 0, &self.config)
            .unwrap_or(false);
        
        // 清理敏感数据
        derived_keys.zeroize();
        
        debug!("V4密钥验证结果: {}", result);
        Ok(result)
    }
    
    fn config(&self) -> &DecryptConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;
    
    #[tokio::test]
    async fn test_v4_decryptor_creation() {
        let decryptor = V4Decryptor::new();
        assert_eq!(decryptor.version(), DecryptVersion::V4);
        assert_eq!(decryptor.config().iter_count, 256000);
        assert_eq!(decryptor.config().hmac_size, 64);
    }
    
    #[tokio::test]
    async fn test_validate_key_with_invalid_file() {
        let decryptor = V4Decryptor::new();
        
        // 创建一个临时文件，内容为SQLite头（已解密）
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"SQLite format 3\x00").await.unwrap();
        temp_file.flush().await.unwrap();
        
        let key = vec![0u8; 32];
        let result = decryptor.validate_key(temp_file.path(), &key).await;
        
        // 应该返回false，因为文件已经解密
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    
    #[tokio::test]
    async fn test_read_db_info() {
        let decryptor = V4Decryptor::new();
        
        // 创建一个临时文件
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![0x42u8; 4096]; // 填充数据
        temp_file.write_all(&test_data).await.unwrap();
        temp_file.flush().await.unwrap();
        
        let result = decryptor.read_db_info(temp_file.path()).await;
        assert!(result.is_ok());
        
        let (file_size, first_page) = result.unwrap();
        assert_eq!(file_size, 4096);
        assert_eq!(first_page.len(), 4096);
        assert_eq!(first_page[0], 0x42);
    }
}