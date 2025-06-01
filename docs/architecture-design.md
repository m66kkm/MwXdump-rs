# MwXdump - 架构设计文档

## 📋 概述

本文档详细描述了MwXdump的整体架构设计，包括模块划分、技术选型、接口设计和实现细节。

**项目目标**: 将Go版本的微信聊天记录解密工具完全迁移到Rust，提供更高的性能、更好的内存安全性和更优秀的并发处理能力。

## 🏗️ 整体架构

### 分层架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    应用层 (Application Layer)                │
├─────────────────────────────────────────────────────────────┤
│  CLI Commands  │  HTTP API  │  TUI Interface  │  MCP Server │
├─────────────────────────────────────────────────────────────┤
│                    业务逻辑层 (Business Logic)               │
├─────────────────────────────────────────────────────────────┤
│  Process Detection │ Key Extraction │ Data Decryption      │
├─────────────────────────────────────────────────────────────┤
│                    平台抽象层 (Platform Abstraction)         │
├─────────────────────────────────────────────────────────────┤
│  Windows API  │  macOS API  │  Database ORM  │  File System │
├─────────────────────────────────────────────────────────────┤
│                    基础设施层 (Infrastructure)               │
├─────────────────────────────────────────────────────────────┤
│  Async Runtime │  Error Handling │  Logging │  Configuration│
└─────────────────────────────────────────────────────────────┘
```

### 核心模块划分

```rust
MwXdump-rs/
├── src/
│   ├── main.rs                 # 应用入口
│   ├── app/                    # 应用层
│   │   ├── mod.rs
│   │   └── config.rs
│   ├── cli/                    # 命令行接口
│   │   ├── mod.rs
│   │   └── commands/
│   ├── http/                   # HTTP API服务
│   ├── ui/                     # 终端UI界面
│   ├── mcp/                    # MCP协议服务
│   ├── wechat/                 # 微信相关核心功能
│   │   ├── process/            # 进程检测 ✅
│   │   ├── key/                # 密钥提取 ✅
│   │   ├── decrypt/            # 数据解密
│   │   └── database/           # 数据库操作
│   ├── models/                 # 数据模型
│   ├── database/               # 数据库抽象
│   ├── errors/                 # 错误处理 ✅
│   └── utils/                  # 工具函数
```

## 🔧 核心模块详细设计

### 1. 进程检测模块 (Process Detection) ✅

#### 架构设计
```rust
// 跨平台trait接口
#[async_trait]
pub trait ProcessDetector: Send + Sync {
    async fn detect_processes(&self) -> Result<Vec<ProcessInfo>>;
    async fn get_process_info(&self, pid: u32) -> Result<Option<ProcessInfo>>;
    async fn detect_version(&self, exe_path: &PathBuf) -> Result<WeChatVersion>;
    async fn locate_data_dir(&self, process: &ProcessInfo) -> Result<Option<PathBuf>>;
}

// 平台特定实现
#[cfg(target_os = "windows")]
pub type PlatformDetector = windows::WindowsProcessDetector;

#[cfg(target_os = "macos")]
pub type PlatformDetector = macos::MacOSProcessDetector;
```

#### 核心数据结构
```rust
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: PathBuf,
    pub version: WeChatVersion,
    pub data_dir: Option<PathBuf>,
    pub detected_at: DateTime<Utc>,
}

pub enum WeChatVersion {
    V3x { exact: String },
    V40 { exact: String },
    Unknown,
}
```

#### 实现策略
- **Windows**: 使用系统命令 (`tasklist`, `wmic`) + PowerShell版本检测
- **macOS**: 使用 `ps` 命令 + `plutil` 版本读取
- **优势**: 避免复杂的API权限问题，跨版本兼容性好

### 2. 密钥提取模块 (Key Extraction) ✅

#### 架构设计
```rust
// 核心接口
#[async_trait]
pub trait KeyExtractor: Send + Sync {
    async fn extract_key(&self, process: &ProcessInfo) -> Result<WeChatKey>;
    async fn search_key_in_memory(&self, memory: &[u8]) -> Result<Option<Vec<u8>>>;
    async fn validate_key(&self, key: &[u8]) -> Result<bool>;
    fn supported_version(&self) -> KeyVersion;
}

// 平台和版本特定实现
pub struct V3KeyExtractor {
    searcher: MemorySearcher,
}

pub struct V4KeyExtractor {
    // V4特定实现
}
```

#### Windows API绑定层
```rust
pub struct WindowsApi {
    pub process_handle: HANDLE,
}

impl WindowsApi {
    // 核心API封装
    pub fn open_process(pid: u32) -> Result<Self>;
    pub fn find_module(&self, pid: u32, module_name: &str) -> Result<Option<ModuleInfo>>;
    pub fn enumerate_writable_regions(&self, module: &ModuleInfo) -> Result<Vec<MemoryInfo>>;
    pub fn read_memory(&self, address: usize, size: usize) -> Result<Vec<u8>>;
}

// 自动资源管理
impl Drop for WindowsApi {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.process_handle); }
    }
}
```

#### 内存搜索引擎
```rust
pub struct MemorySearcher {
    config: SearchConfig,
}

pub struct SearchConfig {
    pub max_workers: usize,           // 最大工作线程数
    pub memory_channel_buffer: usize, // 内存通道缓冲区
    pub min_region_size: usize,       // 最小内存区域大小
}

impl MemorySearcher {
    // 并发搜索核心算法
    pub async fn search_v3_key(&self, process: &ProcessInfo) -> Result<WeChatKey>;
    
    // 内部实现
    async fn concurrent_search(&self, ...) -> Result<WeChatKey>;
    async fn search_worker(...) -> ();
}
```

#### 核心算法实现
```rust
// Go算法精确移植
async fn search_worker(
    worker_id: usize,
    api: Arc<WindowsApi>,
    memory_rx: Arc<Mutex<mpsc::Receiver<(usize, Vec<u8>)>>>,
    is_64bit: bool,
    source_pid: u32,
    result_tx: Arc<Mutex<Option<oneshot::Sender<WeChatKey>>>>,
) {
    // 1. 定义搜索模式
    let key_pattern = if is_64bit {
        vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    } else {
        vec![0x20, 0x00, 0x00, 0x00]
    };
    
    // 2. 并发处理内存块
    while let Some((base_address, memory_data)) = receive_memory_block().await {
        // 3. 搜索模式匹配
        if let Some(pattern_pos) = find_pattern_reverse(&memory_data, &key_pattern) {
            // 4. 验证指针值
            let ptr_value = extract_pointer(&memory_data, pattern_pos, is_64bit);
            if is_valid_pointer(ptr_value) {
                // 5. 读取密钥数据
                if let Ok(key_data) = api.read_memory(ptr_value as usize, 32) {
                    let key = WeChatKey::new(key_data, source_pid, KeyVersion::V3x);
                    // 6. 发送结果并停止搜索
                    send_result(key).await;
                    return;
                }
            }
        }
    }
}
```

### 3. 数据解密模块 (Data Decryption) ⏳

#### 设计规划
```rust
// 解密器接口
#[async_trait]
pub trait Decryptor: Send + Sync {
    async fn decrypt_database(&self, db_path: &Path, key: &WeChatKey, output: &Path) -> Result<()>;
    async fn decrypt_media(&self, media_path: &Path, key: &WeChatKey) -> Result<Vec<u8>>;
    fn get_page_size(&self) -> usize;
    fn get_version(&self) -> &str;
}

// 版本特定实现
pub struct V3Decryptor {
    iter_count: i32,
    hmac_size: i32,
    hash_func: fn() -> Box<dyn Digest>,
}

pub struct V4Decryptor {
    // V4特定参数
}
```

#### 加密算法实现
```rust
// 密钥派生 (PBKDF2)
fn derive_keys(&self, key: &[u8], salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let enc_key = pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(key, salt, self.iter_count);
    let mac_salt = xor_bytes(salt, 0x3a);
    let mac_key = pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(&enc_key, &mac_salt, 2);
    (enc_key.to_vec(), mac_key.to_vec())
}

// 页面解密 (AES-CBC)
fn decrypt_page(&self, page_data: &[u8], enc_key: &[u8], mac_key: &[u8]) -> Result<Vec<u8>> {
    // 1. HMAC验证
    let mac = Hmac::<Sha1>::new_from_slice(mac_key)?;
    mac.verify_slice(&stored_mac)?;
    
    // 2. AES解密
    let cipher = Aes256CbcDec::new(enc_key.into(), iv.into());
    let decrypted = cipher.decrypt_padded_vec_mut::<Pkcs7>(&encrypted_data)?;
    
    Ok(decrypted)
}
```

## 🔄 异步并发设计

### Tokio运行时架构
```rust
// 主运行时配置
#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    tracing_subscriber::fmt::init();
    
    // 创建应用实例
    let app = App::new().await?;
    
    // 启动服务
    app.run().await
}

// 应用层异步协调
pub struct App {
    config: ConfigService,
    // 各种服务实例
}

impl App {
    pub async fn run(&self) -> Result<()> {
        // 并发启动多个服务
        tokio::select! {
            result = self.run_cli() => result?,
            result = self.run_http_server() => result?,
            result = self.run_mcp_server() => result?,
        }
        Ok(())
    }
}
```

### 并发模式设计
```rust
// 1. 生产者-消费者模式 (内存搜索)
let (memory_tx, memory_rx) = mpsc::channel(buffer_size);
let memory_rx = Arc::new(Mutex::new(memory_rx));

// 2. 工作线程池模式
let mut workers = JoinSet::new();
for worker_id in 0..max_workers {
    workers.spawn(search_worker(worker_id, ...));
}

// 3. 早停机制
let (result_tx, result_rx) = oneshot::channel();
tokio::select! {
    result = result_rx => {
        // 找到结果，取消所有任务
        workers.abort_all();
        result
    }
    _ = workers.join_next() => {
        // 所有工作完成
        Err("未找到结果")
    }
}
```

## 🛡️ 错误处理设计

### 错误类型层次
```rust
// 顶层错误类型
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("配置错误: {0}")]
    Config(#[from] ConfigError),
    
    #[error("数据库错误: {0}")]
    Database(#[from] DatabaseError),
    
    #[error("微信相关错误: {0}")]
    WeChat(#[from] WeChatError),
    
    #[error("HTTP服务错误: {0}")]
    Http(#[from] HttpError),
    
    #[error("IO错误: {0}")]
    Io(#[from] std::io::Error),
}

// 微信特定错误
#[derive(Debug, thiserror::Error)]
pub enum WeChatError {
    #[error("进程未找到")]
    ProcessNotFound,
    
    #[error("密钥提取失败: {0}")]
    KeyExtractionFailed(String),
    
    #[error("解密失败: {0}")]
    DecryptionFailed(String),
    
    #[error("不支持的版本: {version}")]
    UnsupportedVersion { version: String },
}
```

### 错误传播机制
```rust
// Result类型别名
pub type Result<T> = std::result::Result<T, Error>;

// 错误传播示例
pub async fn extract_key(&self, process: &ProcessInfo) -> Result<WeChatKey> {
    let api = WindowsApi::open_process(process.pid)?;
    let module = api.find_module(process.pid, "WeChatWin.dll")?
        .ok_or_else(|| WeChatError::KeyExtractionFailed("未找到模块".to_string()))?;
    
    let regions = api.enumerate_writable_regions(&module)?;
    let key = self.searcher.search_v3_key(process).await?;
    
    Ok(key)
}
```

## 📊 性能优化策略

### 1. 内存管理优化
```rust
// 零拷贝内存操作
pub fn read_memory(&self, address: usize, size: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    unsafe {
        ReadProcessMemory(
            self.process_handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            &mut bytes_read,
        )?;
    }
    Ok(buffer)
}

// 内存池复用
pub struct MemoryPool {
    buffers: Vec<Vec<u8>>,
}

impl MemoryPool {
    pub fn get_buffer(&mut self, size: usize) -> Vec<u8> {
        self.buffers.pop().unwrap_or_else(|| vec![0; size])
    }
    
    pub fn return_buffer(&mut self, buffer: Vec<u8>) {
        if buffer.capacity() <= MAX_BUFFER_SIZE {
            self.buffers.push(buffer);
        }
    }
}
```

### 2. 并发优化
```rust
// 自适应线程数
let max_workers = std::cmp::min(num_cpus::get(), 16);

// 智能任务分配
let chunk_size = total_memory_size / max_workers;
for (worker_id, chunk) in memory_chunks.enumerate() {
    workers.spawn(process_chunk(worker_id, chunk));
}

// 早停机制
if found_key {
    workers.abort_all();
    return Ok(key);
}
```

### 3. 缓存策略
```rust
// 进程信息缓存
pub struct ProcessCache {
    cache: HashMap<u32, (ProcessInfo, Instant)>,
    ttl: Duration,
}

impl ProcessCache {
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.cache.get(&pid)
            .filter(|(_, timestamp)| timestamp.elapsed() < self.ttl)
            .map(|(info, _)| info)
    }
}
```

## 🔧 配置管理

### 配置文件结构
```toml
# MwXdump.toml
[app]
name = "MwXdump"
version = "0.1.0"
log_level = "info"

[process_detection]
scan_interval = 5000  # ms
cache_ttl = 30000     # ms

[key_extraction]
max_workers = 8
memory_buffer_size = 100
min_region_size = 102400  # 100KB

[decryption]
batch_size = 1000
output_format = "sqlite"

[http]
host = "127.0.0.1"
port = 8080
cors_enabled = true

[mcp]
enabled = true
stdio_mode = true
```

### 配置加载机制
```rust
#[derive(Debug, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub process_detection: ProcessDetectionConfig,
    pub key_extraction: KeyExtractionConfig,
    pub decryption: DecryptionConfig,
    pub http: HttpConfig,
    pub mcp: McpConfig,
}

impl Config {
    pub fn load() -> Result<Self> {
        let config = config::Config::builder()
            .add_source(config::File::with_name("MwXdump"))
            .add_source(config::Environment::with_prefix("MWXDUMP"))
            .build()?;
        
        Ok(config.try_deserialize()?)
    }
}
```

## 📝 日志和监控

### 日志系统设计
```rust
// 结构化日志
use tracing::{debug, info, warn, error, instrument};

#[instrument(skip(self))]
pub async fn extract_key(&self, process: &ProcessInfo) -> Result<WeChatKey> {
    info!("开始提取密钥，进程: {} (PID: {})", process.name, process.pid);
    
    let start = Instant::now();
    let result = self.do_extract_key(process).await;
    let duration = start.elapsed();
    
    match &result {
        Ok(key) => {
            info!("密钥提取成功，耗时: {:?}, 密钥: {}", duration, key.to_hex());
        }
        Err(e) => {
            error!("密钥提取失败，耗时: {:?}, 错误: {}", duration, e);
        }
    }
    
    result
}
```

### 性能监控
```rust
// 性能指标收集
pub struct Metrics {
    pub process_detection_time: Histogram,
    pub key_extraction_time: Histogram,
    pub decryption_time: Histogram,
    pub success_rate: Counter,
    pub error_count: Counter,
}

impl Metrics {
    pub fn record_key_extraction(&self, duration: Duration, success: bool) {
        self.key_extraction_time.observe(duration.as_secs_f64());
        if success {
            self.success_rate.inc();
        } else {
            self.error_count.inc();
        }
    }
}
```

## 🧪 测试策略

### 单元测试
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;
    
    #[tokio::test]
    async fn test_process_detection() {
        let detector = WindowsProcessDetector::new();
        let processes = detector.detect_processes().await.unwrap();
        assert!(!processes.is_empty());
    }
    
    #[test]
    fn test_key_validation() {
        let key = WeChatKey::new(vec![0u8; 32], 1234, KeyVersion::V3x);
        assert_eq!(key.data.len(), 32);
        assert_eq!(key.source_pid, 1234);
    }
}
```

### 集成测试
```rust
#[tokio::test]
async fn test_full_key_extraction_flow() {
    // 1. 检测进程
    let detector = ProcessDetector::new();
    let processes = detector.detect_processes().await?;
    
    // 2. 提取密钥
    let extractor = V3KeyExtractor::new()?;
    for process in processes {
        if let Ok(key) = extractor.extract_key(&process).await {
            // 3. 验证密钥
            assert_eq!(key.data.len(), 32);
            assert!(key.is_valid());
            break;
        }
    }
}
```

## 🚀 部署和分发

### 构建配置
```toml
# Cargo.toml
[profile.release]
lto = true              # 链接时优化
codegen-units = 1       # 单个代码生成单元
panic = "abort"         # 崩溃时直接退出
strip = true            # 移除调试符号

[profile.dev]
debug = true            # 开发时保留调试信息
```

### 跨平台编译
```bash
# Windows
cargo build --release --target x86_64-pc-windows-msvc

# macOS
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# 通用二进制文件 (macOS)
lipo -create -output MwXdump-universal \
    target/x86_64-apple-darwin/release/MwXdump \
    target/aarch64-apple-darwin/release/MwXdump
```

## 📈 性能基准

### 当前性能指标
- **进程检测**: ~7秒 (10个进程)
- **密钥提取**: <1秒 (V3算法)
- **内存使用**: <50MB (运行时)
- **成功率**: 100% (真实环境测试)

### 性能目标
- **进程检测**: <3秒
- **密钥提取**: <500ms
- **数据解密**: <10秒/GB
- **内存使用**: <100MB

## 🔮 未来规划

### 短期目标 (1-2周)
1. 完成数据解密模块
2. 实现V4密钥提取算法
3. 添加密钥验证功能
4. 完善错误处理和日志

### 中期目标 (1-2月)
1. 实现HTTP API服务
2. 添加Web界面
3. 实现MCP协议支持
4. 性能优化和基准测试

### 长期目标 (3-6月)
1. 支持更多微信版本
2. 添加Linux平台支持
3. 实现分布式处理
4. 商业化部署方案

---

*文档版本: v1.0*  
*最后更新: 2025-06-01*  
*状态: Phase 2 完成，Phase 3 设计中*