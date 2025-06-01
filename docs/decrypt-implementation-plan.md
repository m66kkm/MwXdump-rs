# 数据解密模块实现计划

## 一、实现概述

基于Go代码分析，我们需要实现一个完整的SQLite数据库解密系统，支持微信V3和V4两个版本的加密格式。

## 二、核心组件设计

### 1. 模块结构

```
MwXdump-rs/src/wechat/decrypt/
├── mod.rs              # 模块入口和trait定义
├── common.rs           # 通用解密函数
├── v3.rs               # V3版本解密器
├── v4.rs               # V4版本解密器
├── validator.rs        # 密钥验证器
└── page.rs             # 页面解密逻辑
```

### 2. 核心Trait定义

```rust
// src/wechat/decrypt/mod.rs

use async_trait::async_trait;
use std::path::Path;
use crate::errors::Result;

/// 解密器版本
#[derive(Debug, Clone, Copy)]
pub enum DecryptVersion {
    V3,
    V4,
}

/// 解密器配置
#[derive(Debug, Clone)]
pub struct DecryptConfig {
    pub version: DecryptVersion,
    pub page_size: usize,
    pub iter_count: u32,
    pub hmac_size: usize,
    pub reserve_size: usize,
}

/// 解密器trait
#[async_trait]
pub trait Decryptor: Send + Sync {
    /// 解密数据库
    async fn decrypt_database(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
    ) -> Result<()>;
    
    /// 验证密钥
    async fn validate_key(
        &self,
        db_path: &Path,
        key: &[u8],
    ) -> Result<bool>;
    
    /// 获取配置
    fn config(&self) -> &DecryptConfig;
}

/// 解密进度回调
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;
```

### 3. 通用函数实现

```rust
// src/wechat/decrypt/common.rs

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha512;

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

/// 密钥派生函数
pub fn derive_keys_v3(key: &[u8], salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // 派生加密密钥
    let mut enc_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha1>(key, salt, 64000, &mut enc_key);
    
    // 派生MAC密钥
    let mac_salt: Vec<u8> = salt.iter().map(|&b| b ^ 0x3a).collect();
    let mut mac_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha1>(&enc_key, &mac_salt, 2, &mut mac_key);
    
    Ok((enc_key, mac_key))
}

/// V4版本密钥派生
pub fn derive_keys_v4(key: &[u8], salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut enc_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha512>(key, salt, 256000, &mut enc_key);
    
    let mac_salt: Vec<u8> = salt.iter().map(|&b| b ^ 0x3a).collect();
    let mut mac_key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha512>(&enc_key, &mac_salt, 2, &mut mac_key);
    
    Ok((enc_key, mac_key))
}

/// 验证页面HMAC
pub fn verify_page_hmac(
    page_data: &[u8],
    mac_key: &[u8],
    page_num: u64,
    config: &DecryptConfig,
) -> Result<bool> {
    // 根据版本选择HMAC算法
    match config.version {
        DecryptVersion::V3 => verify_hmac_sha1(page_data, mac_key, page_num, config),
        DecryptVersion::V4 => verify_hmac_sha512(page_data, mac_key, page_num, config),
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
    // 1. 验证HMAC
    if !verify_page_hmac(page_data, mac_key, page_num, config)? {
        return Err(WeChatError::DecryptionFailed("HMAC验证失败".to_string()).into());
    }
    
    // 2. 提取IV和加密数据
    let iv_start = config.page_size - config.reserve_size;
    let iv = &page_data[iv_start..iv_start + IV_SIZE];
    
    // 3. 确定数据偏移（第一页需要跳过Salt）
    let offset = if page_num == 0 { SALT_SIZE } else { 0 };
    let encrypted_data = &page_data[offset..iv_start];
    
    // 4. AES-CBC解密
    type Aes256CbcDec = Decryptor<aes::Aes256>;
    let cipher = Aes256CbcDec::new(enc_key.into(), iv.into());
    
    let mut decrypted = encrypted_data.to_vec();
    cipher.decrypt_padded_mut::<NoPadding>(&mut decrypted)?;
    
    // 5. 组装解密后的页面
    let mut result = decrypted;
    result.extend_from_slice(&page_data[iv_start..]);
    
    Ok(result)
}
```

### 4. V3解密器实现

```rust
// src/wechat/decrypt/v3.rs

use super::*;
use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct V3Decryptor {
    config: DecryptConfig,
}

impl V3Decryptor {
    pub fn new() -> Self {
        Self {
            config: DecryptConfig {
                version: DecryptVersion::V3,
                page_size: 4096,
                iter_count: 64000,
                hmac_size: 20,
                reserve_size: 48, // 对齐后的大小
            },
        }
    }
}

#[async_trait]
impl Decryptor for V3Decryptor {
    async fn decrypt_database(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
    ) -> Result<()> {
        // 1. 打开输入文件
        let mut input_file = File::open(input_path).await?;
        let file_size = input_file.metadata().await?.len();
        let total_pages = (file_size as usize + self.config.page_size - 1) / self.config.page_size;
        
        // 2. 读取第一页获取Salt
        let mut first_page = vec![0u8; self.config.page_size];
        input_file.read_exact(&mut first_page).await?;
        
        // 检查是否已解密
        if first_page.starts_with(SQLITE_HEADER) {
            return Err(WeChatError::DecryptionFailed("数据库已解密".to_string()).into());
        }
        
        let salt = &first_page[..SALT_SIZE];
        
        // 3. 派生密钥
        let (enc_key, mac_key) = derive_keys_v3(key, salt)?;
        
        // 4. 验证密钥
        if !verify_page_hmac(&first_page, &mac_key, 0, &self.config)? {
            return Err(WeChatError::DecryptionFailed("密钥错误".to_string()).into());
        }
        
        // 5. 创建输出文件
        let mut output_file = File::create(output_path).await?;
        
        // 6. 写入SQLite头
        output_file.write_all(SQLITE_HEADER).await?;
        
        // 7. 解密所有页面
        input_file.rewind().await?;
        
        for page_num in 0..total_pages {
            let mut page_data = vec![0u8; self.config.page_size];
            let bytes_read = input_file.read(&mut page_data).await?;
            
            if bytes_read == 0 {
                break;
            }
            
            // 处理最后一页
            if bytes_read < self.config.page_size {
                page_data.truncate(bytes_read);
            }
            
            // 检查是否为空页面
            if page_data.iter().all(|&b| b == 0) {
                output_file.write_all(&page_data).await?;
                continue;
            }
            
            // 解密页面
            let decrypted = decrypt_page(
                &page_data,
                &enc_key,
                &mac_key,
                page_num as u64,
                &self.config,
            )?;
            
            output_file.write_all(&decrypted).await?;
        }
        
        Ok(())
    }
    
    async fn validate_key(
        &self,
        db_path: &Path,
        key: &[u8],
    ) -> Result<bool> {
        let mut file = File::open(db_path).await?;
        let mut first_page = vec![0u8; self.config.page_size];
        file.read_exact(&mut first_page).await?;
        
        let salt = &first_page[..SALT_SIZE];
        let (_, mac_key) = derive_keys_v3(key, salt)?;
        
        verify_page_hmac(&first_page, &mac_key, 0, &self.config)
    }
    
    fn config(&self) -> &DecryptConfig {
        &self.config
    }
}
```

### 5. 密钥验证器

```rust
// src/wechat/decrypt/validator.rs

use super::*;
use std::path::Path;

pub struct KeyValidator {
    v3_decryptor: V3Decryptor,
    v4_decryptor: V4Decryptor,
}

impl KeyValidator {
    pub fn new() -> Self {
        Self {
            v3_decryptor: V3Decryptor::new(),
            v4_decryptor: V4Decryptor::new(),
        }
    }
    
    /// 自动检测版本并验证密钥
    pub async fn validate_key_auto(
        &self,
        db_path: &Path,
        key: &[u8],
    ) -> Result<Option<DecryptVersion>> {
        // 尝试V3
        if self.v3_decryptor.validate_key(db_path, key).await? {
            return Ok(Some(DecryptVersion::V3));
        }
        
        // 尝试V4
        if self.v4_decryptor.validate_key(db_path, key).await? {
            return Ok(Some(DecryptVersion::V4));
        }
        
        Ok(None)
    }
}
```

## 三、实现步骤

### 第1步：基础加密原语（1天）
1. 实现PBKDF2密钥派生
2. 实现HMAC-SHA1和HMAC-SHA512
3. 实现AES-256-CBC解密
4. 单元测试

### 第2步：页面解密功能（1天）
1. 实现页面结构解析
2. 实现单页解密函数
3. 实现HMAC验证
4. 测试已知数据

### 第3步：完整解密器（2天）
1. 实现V3解密器
2. 实现V4解密器
3. 实现密钥验证器
4. 集成测试

### 第4步：性能优化（1天）
1. 实现并发解密
2. 添加进度回调
3. 优化内存使用
4. 性能测试

### 第5步：错误处理和日志（1天）
1. 完善错误类型
2. 添加详细日志
3. 实现错误恢复
4. 最终测试

## 四、测试计划

### 1. 单元测试
- 测试密钥派生算法输出
- 测试HMAC计算结果
- 测试AES解密功能
- 测试页面结构解析

### 2. 集成测试
- 准备加密的测试数据库
- 测试完整解密流程
- 验证解密后数据库可用性
- 测试错误处理

### 3. 兼容性测试
- 测试V3版本数据库
- 测试V4版本数据库
- 与Go版本对比结果

## 五、注意事项

1. **内存安全**：使用`zeroize`清理密钥数据
2. **大文件处理**：使用流式读写避免内存溢出
3. **错误恢复**：部分页面损坏时继续处理
4. **性能监控**：提供解密速度和进度信息

## 六、预期成果

完成后将实现：
- ✅ 支持V3和V4版本数据库解密
- ✅ 自动版本检测和密钥验证
- ✅ 高性能并发解密
- ✅ 完善的错误处理
- ✅ 与Go版本100%兼容

---

*实施时间：约6天*
*最后更新：2025-06-01*