# 第二阶段：微信核心功能实施计划

## 概述

第二阶段将实现微信相关的核心功能，包括进程检测、密钥提取和数据解密。这是整个项目最关键的部分。

## 实施顺序

### 2.1 进程检测模块（第1周）

#### Windows实现
1. **使用Windows API检测进程**
   - 使用 `CreateToolhelp32Snapshot` 枚举进程
   - 通过进程名称匹配微信进程
   - 获取进程ID、路径等信息

2. **版本检测**
   - 读取微信可执行文件版本信息
   - 判断是3.x还是4.0版本

3. **数据目录定位**
   - 根据进程信息找到数据存储目录
   - 通常在 `%APPDATA%\Tencent\WeChat\` 或 `Documents\WeChat Files\`

#### macOS实现
1. **使用系统API检测进程**
   - 使用 `sysctl` 获取进程列表
   - 匹配微信进程

2. **版本和路径检测**
   - 读取 Info.plist 获取版本
   - 定位数据目录

### 2.2 密钥提取模块（第2周）

#### Windows密钥提取
1. **内存读取准备**
   - 使用 `OpenProcess` 获取进程句柄
   - 使用 `ReadProcessMemory` 读取内存

2. **密钥模式匹配**
   - 4.0+版本：搜索特定的密钥模式和存储方式

3. **密钥验证**
   - 使用提取的密钥尝试解密测试数据
   - 确认密钥正确性

#### macOS密钥提取
1. **SIP处理**
   - 检测SIP状态
   - 提供用户指导

2. **内存读取**
   - 使用 `task_for_pid` 获取任务端口
   - 使用 `vm_read` 读取内存

3. **密钥定位**
   - 使用vmmap分析内存布局
   - 搜索密钥特征

### 2.3 数据解密模块（第3周）

1. **AES解密实现**
   - 使用 `aes` crate 实现AES-128-CBC解密
   - 处理不同版本的加密参数

2. **数据库文件解密**
   - 解密 SQLite 数据库文件
   - 处理分页解密

3. **多媒体文件解密**
   - 图片解密（.dat 文件）
   - 语音解密（SILK格式）
   - 视频解密

4. **批量处理**
   - 实现并发解密
   - 进度显示
   - 错误处理

## 技术要点

### 跨平台处理
```rust
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

pub trait ProcessDetector {
    async fn detect_processes(&self) -> Result<Vec<ProcessInfo>>;
}

#[cfg(target_os = "windows")]
pub use windows::WindowsProcessDetector as PlatformDetector;

#[cfg(target_os = "macos")]
pub use macos::MacOSProcessDetector as PlatformDetector;
```

### 内存安全
- 使用 `zeroize` 清理敏感数据
- 避免密钥泄露到日志
- 安全的内存读取错误处理

### 性能优化
- 使用内存映射读取大文件
- 并行处理多个文件
- 缓存解密结果

## 测试策略

1. **单元测试**
   - 测试各个加密算法
   - 测试模式匹配逻辑

2. **集成测试**
   - 使用测试数据验证解密
   - 测试不同版本兼容性

3. **手动测试**
   - 在真实环境测试
   - 验证不同微信版本

## 依赖项

需要添加的额外依赖：
```toml
# 加密相关
aes = "0.8"
cbc = "0.1"
block-modes = "0.9"
zeroize = "1.7"

# Windows特定
[target.'cfg(windows)'.dependencies]
winapi = { version = "0.3", features = ["tlhelp32", "processthreadsapi", "memoryapi"] }

# macOS特定
[target.'cfg(target_os = "macos")'.dependencies]
mach = "0.3"
```

## 风险和挑战

1. **权限问题**
   - Windows: 需要管理员权限读取某些进程
   - macOS: SIP限制

2. **版本兼容性**
   - 微信更新可能改变数据格式
   - 需要持续维护

3. **法律合规**
   - 仅处理用户自己的数据
   - 添加明确的使用警告

## 交付物

1. **可工作的进程检测**
   - 能够检测到运行中的微信进程
   - 正确识别版本和数据目录

2. **密钥提取功能**
   - 成功从内存中提取密钥
   - 支持4.0+版本（不支持3.x版本）

3. **数据解密能力**
   - 能够解密数据库文件
   - 能够解密多媒体文件

4. **文档**
   - API文档
   - 使用说明
   - 故障排除指南