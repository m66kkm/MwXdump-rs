# 微信数据库解密算法分析文档

## 概述

微信数据库使用了基于SQLCipher的加密方案，对SQLite数据库进行页级加密。本文档详细分析Go代码中的解密实现，为Rust版本的开发提供指导。

## 核心算法流程

### 1. 整体解密流程

```
1. 读取加密数据库文件
2. 提取Salt（前16字节）
3. 使用PBKDF2派生加密密钥和MAC密钥
4. 验证密钥正确性（通过第一页的HMAC）
5. 逐页解密数据库
6. 输出解密后的SQLite数据库
```

### 2. 密钥派生算法

#### V4版本（微信4.0+）
```go
// 密钥派生参数
iterCount = 256000  // 高迭代次数
hashFunc = SHA512   // 使用SHA512哈希算法
keySize = 32

// 派生过程
encKey = PBKDF2(key, salt, iterCount, keySize, SHA512)
macSalt = XOR(salt, 0x3a)
macKey = PBKDF2(encKey, macSalt, 2, keySize, SHA512)
```

### 3. 页面结构

每个数据库页面的结构：
```
+------------------+------------------+------------------+
| 加密数据区域      | IV (16字节)      | HMAC            |
| (PageSize-Reserve)| 初始化向量        | (20或64字节)     |
+------------------+------------------+------------------+
```

- **PageSize**: 4096字节（标准SQLite页面大小）
- **Reserve**: IV大小 + HMAC大小，向上对齐到16字节
  - V4: 16 + 64 = 80字节
- **加密数据区域**: PageSize - Reserve

### 4. 页面解密过程

```go
func DecryptPage(pageBuf []byte, encKey []byte, macKey []byte, pageNum int64) ([]byte, error) {
    // 1. 特殊处理第一页（跳过16字节的Salt）
    offset := 0
    if pageNum == 0 {
        offset = 16  // SaltSize
    }
    
    // 2. 验证HMAC
    mac := hmac.New(hashFunc, macKey)
    mac.Write(pageBuf[offset : pageSize-reserve+IVSize])
    mac.Write(LittleEndian(pageNum + 1))  // 页号从1开始
    
    calculatedMAC := mac.Sum(nil)
    storedMAC := pageBuf[pageSize-reserve+IVSize : pageSize-reserve+IVSize+hmacSize]
    
    if !hmac.Equal(calculatedMAC, storedMAC) {
        return nil, "HMAC验证失败"
    }
    
    // 3. AES-CBC解密
    iv := pageBuf[pageSize-reserve : pageSize-reserve+IVSize]
    cipher := AES-256-CBC(encKey, iv)
    
    encrypted := pageBuf[offset : pageSize-reserve]
    decrypted := cipher.Decrypt(encrypted)
    
    // 4. 组装解密后的页面
    // 保留Reserve部分（包含元数据）
    return append(decrypted, pageBuf[pageSize-reserve:pageSize]...)
}
```

### 5. 密钥验证

在解密前需要验证密钥的正确性：

```go
func ValidateKey(page1 []byte, key []byte) bool {
    // 1. 提取Salt
    salt := page1[:16]
    
    // 2. 派生密钥
    _, macKey := deriveKeys(key, salt)
    
    // 3. 计算第一页的HMAC
    mac := hmac.New(hashFunc, macKey)
    mac.Write(page1[16 : pageSize-reserve+IVSize])  // 跳过Salt
    mac.Write([]byte{1, 0, 0, 0})  // 页号1的小端表示
    
    // 4. 比较HMAC
    calculatedMAC := mac.Sum(nil)
    storedMAC := page1[pageSize-reserve+IVSize : pageSize-reserve+IVSize+hmacSize]
    
    return hmac.Equal(calculatedMAC, storedMAC)
}
```

## 关键技术点

### 1. 版本差异

| 特性 | V4版本 |
|------|--------|
| PBKDF2迭代次数 | 256,000 |
| 哈希算法 | SHA512 |
| HMAC大小 | 64字节 |
| Reserve大小 | 80字节 |

**注意**: 本项目仅支持微信4.0+版本，不支持3.x版本。

### 2. 特殊处理

1. **第一页处理**: 第一页包含16字节的Salt，解密时需要跳过
2. **空页面处理**: 全零页面直接写入，不进行解密
3. **页号计算**: HMAC计算时使用的页号从1开始（pageNum + 1）
4. **字节序**: 页号使用小端字节序（LittleEndian）

### 3. 安全考虑

1. **HMAC验证**: 每页都有HMAC保护，确保数据完整性
2. **密钥派生**: 使用PBKDF2增加暴力破解难度
3. **Salt使用**: 每个数据库有独特的Salt，防止彩虹表攻击

## Rust实现建议

### 1. 依赖选择

```toml
[dependencies]
# 加密算法
aes = "0.8"
cbc = "0.1"
hmac = "0.12"
sha1 = "0.10"
sha2 = "0.10"  # 包含SHA512
pbkdf2 = "0.12"

# 工具
hex = "0.4"
byteorder = "1.5"  # 处理字节序
```

### 2. 模块结构

```
src/wechat/decrypt/
├── mod.rs           # 解密器trait定义
├── common.rs        # 通用函数（密钥派生、页面解密）
├── v4.rs            # V4版本实现
└── validator.rs     # 密钥验证
```

### 3. 接口设计

```rust
#[async_trait]
pub trait Decryptor: Send + Sync {
    /// 解密数据库文件
    async fn decrypt_database(
        &self,
        input_path: &Path,
        output_path: &Path,
        key: &[u8],
    ) -> Result<()>;
    
    /// 验证密钥是否正确
    async fn validate_key(
        &self,
        db_path: &Path,
        key: &[u8],
    ) -> Result<bool>;
    
    /// 获取版本信息
    fn version(&self) -> DecryptVersion;
}

pub enum DecryptVersion {
    V4 {
        iter_count: u32,
        hash_algo: HashAlgorithm,
    },
}
```

### 4. 性能优化建议

1. **并发处理**: 可以并发解密多个页面
2. **缓冲区复用**: 使用缓冲池减少内存分配
3. **流式处理**: 支持大文件的流式解密
4. **进度反馈**: 提供解密进度回调

### 5. 错误处理

需要处理的错误类型：
- 文件读写错误
- 密钥格式错误
- HMAC验证失败
- 解密失败
- 数据库格式错误

## 测试策略

### 1. 单元测试

- 测试密钥派生算法
- 测试HMAC计算
- 测试AES解密
- 测试页面结构解析

### 2. 集成测试

- 使用已知密钥的测试数据库
- 验证解密后的数据库可以正常打开
- 测试不同版本的兼容性

### 3. 性能测试

- 测试大文件解密性能
- 测试并发解密性能
- 内存使用情况监控

## 实现步骤建议

1. **第一步**: 实现基础加密原语（PBKDF2、HMAC、AES）
2. **第二步**: 实现密钥验证功能
3. **第三步**: 实现单页解密功能
4. **第四步**: 实现完整数据库解密
5. **第五步**: 添加并发和优化
6. **第六步**: 完善错误处理和日志

## 注意事项

1. **内存安全**: 使用`zeroize`清理敏感数据
2. **文件处理**: 注意大文件的内存使用
3. **兼容性**: 确保与Go版本的行为一致
4. **错误恢复**: 部分页面解密失败时的处理策略

---

*本文档基于Go代码分析，为Rust实现提供技术指导*
*最后更新: 2025-06-01*