//! 通用解密函数和常量

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use byteorder::{LittleEndian, WriteBytesExt};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha512;
use std::io::Cursor;
use tracing::{debug, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{Result, WeChatError};
use super::DecryptConfig;

/// AES块大小
pub const AES_BLOCK_SIZE: usize = 16;
/// Salt大小
pub const SALT_SIZE: usize = 16;
/// IV大小
pub const IV_SIZE: usize = 16;
/// 密钥大小
pub const KEY_SIZE: usize = 32;
/// SQLite头部
pub const SQLITE_HEADER: &[u8] = b"SQLite format 3\x00";

/// 密钥派生结果
pub struct DerivedKeys {
    pub enc_key: Vec<u8>,
    pub mac_key: Vec<u8>,
}

impl Zeroize for DerivedKeys {
    fn zeroize(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// V3版本密钥派生
pub fn derive_keys_v3(key: &[u8], salt: &[u8]) -> Result<DerivedKeys> {
    if key.len() != KEY_SIZE {
        return Err(WeChatError::DecryptionFailed(format!("密钥长度错误: {}, 期望: {}", key.len(), KEY_SIZE)).into());
    }
    
    if salt.len() != SALT_SIZE {
        return Err(WeChatError::DecryptionFailed(format!("Salt长度错误: {}, 期望: {}", salt.len(), SALT_SIZE)).into());
    }
    
    debug!("开始V3密钥派生，迭代次数: 64000");
    
    // 派生加密密钥
    let mut enc_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha1>(key, salt, 64000, &mut enc_key);
    
    // 派生MAC密钥
    let mac_salt: Vec<u8> = salt.iter().map(|&b| b ^ 0x3a).collect();
    let mut mac_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha1>(&enc_key, &mac_salt, 2, &mut mac_key);
    
    debug!("V3密钥派生完成");
    
    Ok(DerivedKeys { enc_key, mac_key })
}

/// V4版本密钥派生
pub fn derive_keys_v4(key: &[u8], salt: &[u8]) -> Result<DerivedKeys> {
    if key.len() != KEY_SIZE {
        return Err(WeChatError::DecryptionFailed(format!("密钥长度错误: {}, 期望: {}", key.len(), KEY_SIZE)).into());
    }
    
    if salt.len() != SALT_SIZE {
        return Err(WeChatError::DecryptionFailed(format!("Salt长度错误: {}, 期望: {}", salt.len(), SALT_SIZE)).into());
    }
    
    debug!("开始V4密钥派生，迭代次数: 256000");
    
    // 派生加密密钥
    let mut enc_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha512>(key, salt, 256000, &mut enc_key);
    
    // 派生MAC密钥
    let mac_salt: Vec<u8> = salt.iter().map(|&b| b ^ 0x3a).collect();
    let mut mac_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha512>(&enc_key, &mac_salt, 2, &mut mac_key);
    
    debug!("V4密钥派生完成");
    
    Ok(DerivedKeys { enc_key, mac_key })
}

/// 根据版本派生密钥
pub fn derive_keys(key: &[u8], salt: &[u8], config: &DecryptConfig) -> Result<DerivedKeys> {
    match config.version {
        super::DecryptVersion::V3 => derive_keys_v3(key, salt),
        super::DecryptVersion::V4 => derive_keys_v4(key, salt),
    }
}

/// 验证页面HMAC（SHA1版本）
fn verify_hmac_sha1(
    page_data: &[u8],
    mac_key: &[u8],
    page_num: u64,
    config: &DecryptConfig,
) -> Result<bool> {
    let mut mac = Hmac::<Sha1>::new_from_slice(mac_key)
        .map_err(|e| WeChatError::DecryptionFailed(format!("创建HMAC失败: {}", e)))?;
    
    // 确定数据偏移（第一页需要跳过Salt）
    let offset = if page_num == 0 { SALT_SIZE } else { 0 };
    let data_end = config.page_size - config.reserve_size + IV_SIZE;
    
    // 检查数据边界，防止越界
    if offset >= page_data.len() {
        return Err(WeChatError::DecryptionFailed(
            format!("页面数据太小: 偏移 {} >= 数据长度 {}", offset, page_data.len())
        ).into());
    }
    
    let actual_end = std::cmp::min(data_end, page_data.len());
    if offset >= actual_end {
        return Err(WeChatError::DecryptionFailed(
            format!("页面数据范围无效: 偏移 {} >= 实际结束位置 {}", offset, actual_end)
        ).into());
    }
    
    // 添加页面数据
    mac.update(&page_data[offset..actual_end]);
    
    // 添加页号（小端序，从1开始）
    let mut page_num_bytes = Vec::new();
    page_num_bytes.write_u32::<LittleEndian>((page_num + 1) as u32)
        .map_err(|e| WeChatError::DecryptionFailed(format!("写入页号失败: {}", e)))?;
    mac.update(&page_num_bytes);
    
    // 计算HMAC
    let calculated_mac = mac.finalize().into_bytes();
    
    // 提取存储的HMAC
    let hmac_start = data_end;
    let hmac_end = hmac_start + config.hmac_size;
    
    if hmac_end > page_data.len() {
        return Err(WeChatError::DecryptionFailed("页面数据不完整".to_string()).into());
    }
    
    let stored_mac = &page_data[hmac_start..hmac_end];
    
    // 比较HMAC
    Ok(calculated_mac.as_slice() == stored_mac)
}

/// 验证页面HMAC（SHA512版本）
fn verify_hmac_sha512(
    page_data: &[u8],
    mac_key: &[u8],
    page_num: u64,
    config: &DecryptConfig,
) -> Result<bool> {
    let mut mac = Hmac::<Sha512>::new_from_slice(mac_key)
        .map_err(|e| WeChatError::DecryptionFailed(format!("创建HMAC失败: {}", e)))?;
    
    // 确定数据偏移（第一页需要跳过Salt）
    let offset = if page_num == 0 { SALT_SIZE } else { 0 };
    let data_end = config.page_size - config.reserve_size + IV_SIZE;
    
    // 检查数据边界，防止越界
    if offset >= page_data.len() {
        return Err(WeChatError::DecryptionFailed(
            format!("页面数据太小: 偏移 {} >= 数据长度 {}", offset, page_data.len())
        ).into());
    }
    
    let actual_end = std::cmp::min(data_end, page_data.len());
    if offset >= actual_end {
        return Err(WeChatError::DecryptionFailed(
            format!("页面数据范围无效: 偏移 {} >= 实际结束位置 {}", offset, actual_end)
        ).into());
    }
    
    // 添加页面数据
    mac.update(&page_data[offset..actual_end]);
    
    // 添加页号（小端序，从1开始）
    let mut page_num_bytes = Vec::new();
    page_num_bytes.write_u32::<LittleEndian>((page_num + 1) as u32)
        .map_err(|e| WeChatError::DecryptionFailed(format!("写入页号失败: {}", e)))?;
    mac.update(&page_num_bytes);
    
    // 计算HMAC
    let calculated_mac = mac.finalize().into_bytes();
    
    // 提取存储的HMAC
    let hmac_start = actual_end;
    let hmac_end = hmac_start + config.hmac_size;
    
    if hmac_end > page_data.len() {
        return Err(WeChatError::DecryptionFailed("页面数据不完整".to_string()).into());
    }
    
    let stored_mac = &page_data[hmac_start..hmac_end];
    
    // 比较HMAC（只比较前config.hmac_size字节）
    Ok(&calculated_mac.as_slice()[..config.hmac_size] == stored_mac)
}

/// 验证页面HMAC
pub fn verify_page_hmac(
    page_data: &[u8],
    mac_key: &[u8],
    page_num: u64,
    config: &DecryptConfig,
) -> Result<bool> {
    match config.version {
        super::DecryptVersion::V3 => verify_hmac_sha1(page_data, mac_key, page_num, config),
        super::DecryptVersion::V4 => verify_hmac_sha512(page_data, mac_key, page_num, config),
    }
}

/// 解密单个页面
pub fn decrypt_page(
    page_data: &[u8],
    enc_key: &[u8],
    mac_key: &[u8],
    page_num: u64,
    config: &DecryptConfig,
) -> Result<Vec<u8>> {
    debug!("解密页面 {}, 大小: {} 字节", page_num, page_data.len());
    
    // 1. 验证HMAC
    if !verify_page_hmac(page_data, mac_key, page_num, config)? {
        return Err(WeChatError::DecryptionFailed(format!("页面 {} HMAC验证失败", page_num)).into());
    }
    
    // 2. 提取IV
    let iv_start = config.page_size - config.reserve_size;
    if iv_start + IV_SIZE > page_data.len() {
        return Err(WeChatError::DecryptionFailed(format!("页面 {} IV位置超出范围", page_num)).into());
    }
    
    let iv = &page_data[iv_start..iv_start + IV_SIZE];
    
    // 3. 确定数据偏移（第一页需要跳过Salt）
    let offset = if page_num == 0 { SALT_SIZE } else { 0 };
    
    // 检查数据边界
    if offset >= page_data.len() {
        return Err(WeChatError::DecryptionFailed(
            format!("页面 {} 数据偏移超出范围: {} >= {}", page_num, offset, page_data.len())
        ).into());
    }
    
    if offset >= iv_start {
        return Err(WeChatError::DecryptionFailed(
            format!("页面 {} 数据范围无效: 偏移 {} >= IV开始位置 {}", page_num, offset, iv_start)
        ).into());
    }
    
    let encrypted_data = &page_data[offset..iv_start];
    
    // 4. AES-256-CBC解密
    type Aes256CbcDec = Decryptor<aes::Aes256>;
    let cipher = Aes256CbcDec::new(enc_key.into(), iv.into());
    
    let mut decrypted = encrypted_data.to_vec();
    
    // 确保数据长度是16的倍数
    let remainder = decrypted.len() % AES_BLOCK_SIZE;
    if remainder != 0 {
        warn!("页面 {} 数据长度不是16的倍数，补零", page_num);
        decrypted.resize(decrypted.len() + (AES_BLOCK_SIZE - remainder), 0);
    }
    
    cipher.decrypt_padded_mut::<NoPadding>(&mut decrypted)
        .map_err(|e| WeChatError::DecryptionFailed(format!("页面 {} AES解密失败: {}", page_num, e)))?;
    
    // 5. 组装解密后的页面
    let mut result = decrypted;
    result.extend_from_slice(&page_data[iv_start..]);
    
    debug!("页面 {} 解密完成，输出大小: {} 字节", page_num, result.len());
    
    Ok(result)
}

/// 检查数据库是否已解密
pub fn is_database_encrypted(first_page: &[u8]) -> bool {
    !first_page.starts_with(SQLITE_HEADER)
}

/// XOR操作辅助函数
pub fn xor_bytes(data: &[u8], value: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ value).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constants() {
        assert_eq!(AES_BLOCK_SIZE, 16);
        assert_eq!(SALT_SIZE, 16);
        assert_eq!(IV_SIZE, 16);
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(SQLITE_HEADER, b"SQLite format 3\x00");
    }
    
    #[test]
    fn test_xor_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let result = xor_bytes(&data, 0x3a);
        assert_eq!(result, vec![0x3b, 0x38, 0x39, 0x3e]);
    }
    
    #[test]
    fn test_is_database_encrypted() {
        let encrypted = vec![0x01, 0x02, 0x03, 0x04];
        assert!(is_database_encrypted(&encrypted));
        
        let decrypted = b"SQLite format 3\x00test";
        assert!(!is_database_encrypted(decrypted));
    }
    
    #[tokio::test]
    async fn test_derive_keys_v3() {
        let key = vec![0u8; KEY_SIZE];
        let salt = vec![0u8; SALT_SIZE];
        
        let result = derive_keys_v3(&key, &salt);
        assert!(result.is_ok());
        
        let derived = result.unwrap();
        assert_eq!(derived.enc_key.len(), KEY_SIZE);
        assert_eq!(derived.mac_key.len(), KEY_SIZE);
    }
    
    #[tokio::test]
    async fn test_derive_keys_v4() {
        let key = vec![0u8; KEY_SIZE];
        let salt = vec![0u8; SALT_SIZE];
        
        let result = derive_keys_v4(&key, &salt);
        assert!(result.is_ok());
        
        let derived = result.unwrap();
        assert_eq!(derived.enc_key.len(), KEY_SIZE);
        assert_eq!(derived.mac_key.len(), KEY_SIZE);
    }
}