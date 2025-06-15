# 微信数据目录查找功能增强方案

## 1. 概述

本方案旨在增强 `find_wechat_data_directory` 函数，添加通过 xwechat 配置文件查找微信数据目录的功能。

## 2. 架构设计

### 2.1 基础文件操作模块 (utils/windows/file.rs)

需要实现以下功能：

```rust
/// 获取当前用户的主目录
/// 返回类似 C:\Users\USERNAME 的路径
pub fn get_user_profile_dir() -> Result<PathBuf>

/// 递归获取指定目录下指定扩展名的文件列表
/// 返回文件的绝对路径集合
pub fn list_files(dir: &Path, extension: &str, recursive: bool) -> Result<Vec<PathBuf>>

/// 读取文件内容，返回字节数组
pub fn read_file_content(path: &Path) -> Result<Vec<u8>>

/// 获取文件的修改时间
pub fn get_file_modified_time(path: &Path) -> Result<SystemTime>

/// 检查目录是否存在
pub fn check_directory_exists(path: &Path) -> bool

/// 在指定目录下查找以特定前缀开头的子目录
pub fn find_directories_with_prefix(parent: &Path, prefix: &str) -> Result<Vec<PathBuf>>
```

### 2.2 微信数据目录查找逻辑增强

在 `WindowsProcessDetector` 中增加以下方法：

```rust
/// 从 xwechat 配置文件中查找数据目录
fn find_from_xwechat_config(&self) -> Result<Option<PathBuf>>

/// 验证微信数据目录
/// 检查 base_dir\xwechat_files\wxid_* 格式的目录是否存在
fn validate_wechat_data_directory(&self, base_dir: &Path) -> Result<Option<PathBuf>>
```

### 2.3 查找流程

1. **获取配置目录**
   - 获取用户主目录：`C:\Users\USERNAME`
   - 构建配置路径：`AppData\Roaming\Tencent\xwechat\config`

2. **读取 INI 文件**
   - 使用 `list_files` 递归获取所有 `.ini` 文件
   - 读取每个文件的内容（字节数组转字符串）
   - 过滤空内容

3. **收集潜在目录**
   - 解析 INI 文件内容（如 "B:\" 或其他路径）
   - 获取 INI 文件的修改时间
   - 构建 (路径, 修改时间) 元组列表

4. **验证数据目录**
   - 按修改时间降序排序（最新的优先）
   - 对每个潜在目录进行验证：
     - 检查 `{base_dir}\xwechat_files` 是否存在
     - 查找 `wxid_` 开头的子目录
     - 返回找到的第一个有效目录

5. **集成到主查找函数**
   - 保持现有查找顺序：
     1. 注册表查找
     2. xwechat 配置查找（新增）
     3. 进程路径推断

## 3. 实现细节

### 3.1 错误处理
- 使用 `Result` 类型进行错误传播
- 在查找失败时记录警告日志但不中断流程
- 确保一种方法失败不影响其他方法

### 3.2 性能考虑
- 文件操作在 `spawn_blocking` 中执行
- 避免不必要的递归深度
- 缓存已验证的结果（如需要）

### 3.3 日志记录
- 记录每个查找步骤的结果
- 包含 PID 信息便于调试
- 区分 info、warn 级别

## 4. 测试场景

1. **正常场景**
   - xwechat config 目录存在且包含有效 INI 文件
   - INI 文件指向的目录包含 wxid_ 子目录

2. **边界场景**
   - config 目录不存在
   - INI 文件为空或包含无效路径
   - 多个 INI 文件存在，验证优先级
   - 路径包含中文或特殊字符

3. **异常场景**
   - 权限不足
   - 网络驱动器路径
   - 循环引用或过深的目录结构

## 5. 版本兼容性

- 支持 Windows 7 及以上版本
- 兼容不同版本的微信客户端
- 保持与现有代码的向后兼容性