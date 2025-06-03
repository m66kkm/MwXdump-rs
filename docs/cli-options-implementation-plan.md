# CLI Options 实现方案

## 📊 现状分析

### 当前CLI结构
```rust
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,
    
    #[arg(short, long, default_value = "info")]
    pub log_level: String,
    
    #[command(subcommand)]
    pub command: Option<Commands>,
}
```

### 问题识别
1. **全局选项未处理** - `config` 和 `log_level` 选项已定义但未在 `execute()` 方法中处理
2. **日志初始化时机** - 日志系统在解析CLI参数之前就初始化了
3. **配置加载缺失** - 没有根据 `--config` 选项加载配置文件
4. **选项传递缺失** - 全局选项没有传递给子命令

## 🎯 实施方案

### 阶段一：重构日志初始化

**当前问题：**
```rust
// main.rs 第22行
init_tracing()?;  // 在解析CLI之前初始化
let cli = Cli::parse();
```

**解决方案：**
```rust
// 先解析CLI参数
let cli = Cli::parse();

// 根据CLI参数初始化日志
init_tracing(&cli.log_level)?;

// 执行命令
cli.execute().await?;
```

### 阶段二：实现配置文件加载

**在 `Cli::execute()` 方法开始时添加：**
```rust
impl Cli {
    pub async fn execute(self) -> Result<()> {
        // 1. 加载配置文件（如果指定）
        let config_service = if let Some(config_path) = &self.config {
            Some(ConfigService::load_from_file(config_path)?)
        } else {
            None
        };
        
        // 2. 创建执行上下文
        let context = ExecutionContext {
            config_service,
            log_level: self.log_level.clone(),
        };
        
        // 3. 执行子命令
        match self.command {
            // ... 现有逻辑，传递context
        }
    }
}
```

### 阶段三：创建执行上下文

**新增结构体：**
```rust
/// CLI执行上下文
pub struct ExecutionContext {
    /// 配置服务
    pub config_service: Option<ConfigService>,
    /// 日志级别
    pub log_level: String,
}

impl ExecutionContext {
    /// 获取配置
    pub fn config(&self) -> &AppConfig {
        self.config_service
            .as_ref()
            .map(|cs| cs.config())
            .unwrap_or(&AppConfig::default())
    }
    
    /// 获取日志级别
    pub fn log_level(&self) -> &str {
        &self.log_level
    }
}
```

### 阶段四：更新子命令接口

**当前接口：**
```rust
pub async fn execute() -> Result<()>
```

**新接口：**
```rust
pub async fn execute(context: &ExecutionContext) -> Result<()>
```

**示例更新 - key命令：**
```rust
// src/cli/commands/key.rs
pub async fn
execute(context: &ExecutionContext) -> Result<()> {
    // 使用配置中的设置
    let config = context.config();
    
    // 根据配置调整行为
    if let Some(data_dir) = &config.wechat.data_dir {
        println!("使用配置的微信数据目录: {:?}", data_dir);
    }
    
    // 现有逻辑...
}
```

## 📋 详细实施步骤

### 步骤1：创建执行上下文结构

**文件：** `src/cli/context.rs`
```rust
//! CLI执行上下文

use crate::config::{AppConfig, ConfigService};
use crate::errors::Result;

/// CLI执行上下文
#[derive(Debug)]
pub struct ExecutionContext {
    /// 配置服务
    config_service: Option<ConfigService>,
    /// 日志级别
    log_level: String,
    /// 默认配置
    default_config: AppConfig,
}

impl ExecutionContext {
    /// 创建新的执行上下文
    pub fn new(config_path: Option<String>, log_level: String) -> Result<Self> {
        let config_service = if let Some(path) = config_path {
            Some(ConfigService::load_from_file(path)?)
        } else {
            None
        };
        
        Ok(Self {
            config_service,
            log_level,
            default_config: AppConfig::default(),
        })
    }
    
    /// 获取配置
    pub fn config(&self) -> &AppConfig {
        self.config_service
            .as_ref()
            .map(|cs| cs.config())
            .unwrap_or(&self.default_config)
    }
    
    /// 获取日志级别
    pub fn log_level(&self) -> &str {
        &self.log_level
    }
    
    /// 获取微信数据目录
    pub fn wechat_data_dir(&self) -> Option<&std::path::Path> {
        self.config().wechat.data_dir.as_deref()
    }
    
    /// 获取微信数据密钥
    pub fn wechat_data_key(&self) -> Option<&str> {
        self.config().wechat.data_key.as_deref()
    }
}
```

### 步骤2：重构main.rs

**修改 `src/main.rs`：**
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 解析命令行参数
    let cli = Cli::parse();
    
    // 根据CLI参数初始化日志
    init_tracing(&cli.log_level)?;
    
    info!("MwXdump 启动，日志级别: {}", cli.log_level);
    
    // 执行命令
    if let Err(e) = cli.execute().await {
        // ... 现有错误处理逻辑
    }
    
    Ok(())
}

fn init_tracing(log_level: &str) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    
    let env_filter = format!("MwXdump={}", log_level);
    
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| env_filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    Ok(())
}
```

###
步骤3：重构CLI模块

**修改 `src/cli/mod.rs`：**
```rust
use crate::cli::context::ExecutionContext;

impl Cli {
    /// 执行命令
    pub async fn execute(self) -> Result<()> {
        // 创建执行上下文
        let context = ExecutionContext::new(self.config, self.log_level)?;
        
        match self.command {
            Some(Commands::Key) => {
                commands::key::execute(&context).await
            }
            Some(Commands::Process) => {
                commands::process::execute(&context).await
            }
            Some(Commands::Decrypt { input, output, key, version, validate_only, threads }) => {
                let args = commands::decrypt::DecryptArgs {
                    input, output, key, version, validate_only, threads,
                };
                commands::decrypt::handle_decrypt(&context, args).await
            }
            Some(Commands::Version) => {
                commands::version::execute(&context).await
            }
            Some(Commands::DumpMemory { pid }) => {
                commands::dump_memory::execute(&context, pid).await
            }
            None => {
                // 没有子命令时显示帮助
                println!("{}", Self::command().render_help());
                Ok(())
            }
        }
    }
}
```

### 步骤4：更新所有子命令

**1. 更新 key 命令 (`src/cli/commands/key.rs`)：**
```rust
use crate::cli::context::ExecutionContext;

pub async fn execute(context: &ExecutionContext) -> Result<()> {
    println!("开始测试微信密钥提取功能...");
    
    // 使用配置中的设置
    let config = context.config();
    
    // 如果配置中有预设的数据密钥，显示提示
    if let Some(preset_key) = context.wechat_data_key() {
        println!("检测到配置文件中的预设密钥: {}...", &preset_key[..8]);
    }
    
    // 如果配置中有数据目录，优先使用
    if let Some(data_dir) = context.wechat_data_dir() {
        println!("使用配置的微信数据目录: {:?}", data_dir);
    }
    
    // 现有逻辑...
}
```

**2. 更新 process 命令 (`src/cli/commands/process.rs`)：**
```rust
use crate::cli::context::ExecutionContext;

pub async fn execute(context: &ExecutionContext) -> Result<()> {
    println!("开始测试进程检测功能...");
    
    // 使用配置中的日志级别
    tracing::info!("当前日志级别: {}", context.log_level());
    
    // 现有逻辑...
}
```

**3. 更新其他命令类似地添加 context 参数**

### 步骤5：增强配置文件功能

**示例配置文件 `config.toml`：**
```toml
[http]
host = "127.0.0.1"
port = 5030
enable_cors = true

[database]
work_dir = "./work"
pool_size = 10
connection_timeout = 30

[wechat]
data_dir = "C:/Users/Username/Documents/WeChat Files"
data_key = "your_preset_key_here"
auto_decrypt = false
supported_versions = ["3.x", "4.0"]

[logging]
level = "debug"
console = true
file = "logs/mwxdump.log"
```

## 🔧
使用示例

### 基本使用
```bash
# 使用默认设置
mwx-cli key

# 指定日志级别
mwx-cli --log-level debug key

# 使用配置文件
mwx-cli --config ./config.toml key

# 组合使用
mwx-cli --config ./config.toml --log-level trace process
```

### 配置文件优先级
1. **命令行参数** > **配置文件** > **默认值**
2. 日志级别：CLI参数覆盖配置文件设置
3. 其他选项：优先使用配置文件中的设置

## 📊 实施时间表

### 第一周：基础架构
- [ ] 创建 `ExecutionContext` 结构
- [ ] 重构 `main.rs` 日志初始化
- [ ] 更新 CLI 模块结构

### 第二周：子命令更新
- [ ] 更新 `key` 命令
- [ ] 更新 `process` 命令
- [ ] 更新 `decrypt` 命令
- [ ] 更新其他命令

### 第三周：测试和优化
- [ ] 添加单元测试
- [ ] 集成测试
- [ ] 文档更新
- [ ] 性能优化

## 🎯 预期效果

### 功能改进
1. **配置文件支持** - 用户可以通过配置文件预设常用选项
2. **灵活的日志控制** - 运行时指定日志级别
3. **统一的上下文传递** - 所有子命令都能访问全局配置
4. **更好的用户体验** - 减少重复输入参数

### 代码质量提升
1. **单一职责** - 每个模块专注于特定功能
2. **依赖注入** - 通过上下文传递依赖
3. **可测试性** - 更容易进行单元测试
4. **可扩展性** - 易于添加新的全局选项

## 🔍 技术细节

### 错误处理策略
```rust
// 配置文件加载失败时的处理
match ExecutionContext::new(config_path, log_level) {
    Ok(context) => context,
    Err(e) => {
        eprintln!("配置加载失败: {}", e);
        eprintln!("使用默认配置继续执行...");
        ExecutionContext::with_defaults(log_level)
    }
}
```

### 日志级别动态调整
```rust
// 支持运行时调整日志级别
impl ExecutionContext {
    pub fn update_log_level(&self, new_level: &str) -> Result<()> {
        // 重新初始化tracing subscriber
        // 这需要特殊处理，因为tracing只能初始化一次
    }
}
```

### 配置文件热重载（可选功能）
```rust
// 监听配置文件变化
impl ConfigService {
    pub fn watch_for_changes(&mut self) -> Result<()> {
        // 使用notify crate监听文件变化
        // 自动重新加载配置
    }
}
```

## 📋 验收标准

### 功能验收
- [ ] `--config` 选项能正确加载配置文件
- [ ] `--log-level` 选项能正确设置日志级别
- [ ] 配置文件中的设置能
被正确应用到子命令
- [ ] 命令行参数优先级正确（CLI > 配置文件 > 默认值）
- [ ] 错误处理完善（配置文件不存在、格式错误等）

### 性能验收
- [ ] 配置文件加载不影响启动速度
- [ ] 日志级别调整即时生效
- [ ] 内存使用合理

### 兼容性验收
- [ ] 现有命令行接口保持兼容
- [ ] 不使用配置文件时功能正常
- [ ] 跨平台兼容性（Windows/macOS/Linux）

## 🚀 后续扩展计划

### 短期扩展
1. **环境变量支持** - 支持通过环境变量设置选项
2. **配置文件模板** - 提供配置文件生成命令
3. **配置验证** - 增强配置文件验证功能

### 长期扩展
1. **配置文件加密** - 支持敏感信息加密存储
2. **多配置文件** - 支持配置文件继承和合并
3. **图形化配置** - 提供配置文件编辑界面

## 📚 相关文档

- [配置文件格式说明](./config-format.md)
- [CLI使用指南](./cli-usage-guide.md)
- [开发者指南](./developer-guide.md)

## 🏁 总结

通过实施这个方案，我们将：

1. **解决当前问题** - 让 `--config` 和 `--log-level` 选项真正起作用
2. **提升用户体验** - 提供灵活的配置方式
3. **改善代码架构** - 建立清晰的上下文传递机制
4. **为未来扩展奠定基础** - 易于添加新的全局选项和功能

这个方案采用渐进式实施，确保每个步骤都可以独立验证，降低实施风险。

---

**文档版本**: v1.0  
**创建时间**: 2025-06-03  
**预计实施时间**: 3周  
**优先级**: 高  
**状态**: 待实施