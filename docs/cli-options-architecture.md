# CLI Options 架构设计图

## 当前架构问题

```mermaid
graph TD
    A[main.rs] --> B[init_tracing 固定参数]
    A --> C[Cli::parse]
    C --> D[Cli::execute]
    D --> E[子命令执行]
    
    B -.->|问题| F[日志级别无法动态设置]
    D -.->|问题| G[全局选项未处理]
    E -.->|问题| H[无法访问配置信息]
    
    style F fill:#ffcccc
    style G fill:#ffcccc
    style H fill:#ffcccc
```

## 重构后架构

```mermaid
graph TD
    A[main.rs] --> B[Cli::parse]
    B --> C[init_tracing 动态参数]
    C --> D[Cli::execute]
    D --> E[ExecutionContext::new]
    E --> F[加载配置文件]
    E --> G[设置日志级别]
    D --> H[子命令执行 + Context]
    
    F --> I[ConfigService]
    I --> J[AppConfig]
    
    H --> K[commands::key::execute context]
    H --> L[commands::process::execute context]
    H --> M[其他子命令 + context]
    
    style E fill:#ccffcc
    style F fill:#ccffcc
    style G fill:#ccffcc
    style H fill:#ccffcc
```

## 执行上下文架构

```mermaid
classDiagram
    class ExecutionContext {
        -config_service: Option~ConfigService~
        -log_level: String
        -default_config: AppConfig
        +new(config_path, log_level) ExecutionContext
        +config() &AppConfig
        +log_level() &str
        +wechat_data_dir() Option~Path~
        +wechat_data_key() Option~str~
    }
    
    class ConfigService {
        -config: AppConfig
        -config_path: Option~PathBuf~
        +load_from_file(path) ConfigService
        +config() &AppConfig
        +update_config(f) Result
        +save() Result
    }
    
    class AppConfig {
        +http: HttpConfig
        +database: DatabaseConfig
        +wechat: WeChatConfig
        +logging: LoggingConfig
        +from_file(path) AppConfig
        +validate() Result
    }
    
    ExecutionContext --> ConfigService : contains
    ConfigService --> AppConfig : manages
    
    note for ExecutionContext : "统一的执行上下文\n传递给所有子命令"
    note for ConfigService : "配置文件管理\n支持加载和保存"
    note for AppConfig : "应用配置结构\n包含所有设置项"
```

## 配置优先级流程

```mermaid
flowchart LR
    A[CLI参数] --> B{参数存在?}
    B -->|是| C[使用CLI参数]
    B -->|否| D[检查配置文件]
    D --> E{配置文件存在?}
    E -->|是| F[使用配置文件值]
    E -->|否| G[使用默认值]
    
    C --> H[最终值]
    F --> H
    G --> H
    
    style A fill:#e1f5fe
    style C fill:#c8e6c9
    style F fill:#fff3e0
    style G fill:#fce4ec
    style H fill:#f3e5f5
```

## 子命令执行流程

```mermaid
sequenceDiagram
    participant Main as
main.rs
    participant CLI as Cli
    participant Context as ExecutionContext
    participant Config as ConfigService
    participant Cmd as SubCommand
    
    Main->>CLI: parse()
    Main->>Main: init_tracing(log_level)
    Main->>CLI: execute()
    
    CLI->>Context: new(config_path, log_level)
    Context->>Config: load_from_file() [if config_path]
    Config-->>Context: ConfigService
    Context-->>CLI: ExecutionContext
    
    CLI->>Cmd: execute(&context)
    Cmd->>Context: config()
    Context-->>Cmd: &AppConfig
    Cmd->>Context: wechat_data_dir()
    Context-->>Cmd: Option<Path>
    Cmd-->>CLI: Result<()>
    CLI-->>Main: Result<()>
    
    Note over Context: 统一的配置访问点
    Note over Config: 配置文件管理
    Note over Cmd: 所有子命令都接收context
```

## 日志系统重构

```mermaid
graph LR
    A[CLI解析] --> B[获取log_level]
    B --> C[init_tracing动态参数]
    C --> D[tracing_subscriber配置]
    D --> E[日志系统就绪]
    
    F[配置文件] --> G[logging.level]
    G --> H{CLI参数存在?}
    H -->|是| I[使用CLI参数]
    H -->|否| J[使用配置文件]
    I --> B
    J --> B
    
    style C fill:#c8e6c9
    style E fill:#c8e6c9
```

## 错误处理流程

```mermaid
flowchart TD
    A[加载配置文件] --> B{文件存在?}
    B -->|否| C[文件不存在错误]
    B -->|是| D[解析配置文件]
    D --> E{格式正确?}
    E -->|否| F[解析错误]
    E -->|是| G[验证配置]
    G --> H{配置有效?}
    H -->|否| I[验证错误]
    H -->|是| J[配置加载成功]
    
    C --> K[使用默认配置]
    F --> K
    I --> K
    K --> L[继续执行]
    J --> L
    
    style C fill:#ffcdd2
    style F fill:#ffcdd2
    style I fill:#ffcdd2
    style K fill:#fff3e0
    style J fill:#c8e6c9
    style L fill:#e8f5e8
```

## 配置文件结构

```mermaid
graph TD
    A[config.toml] --> B[http]
    A --> C[database]
    A --> D[wechat]
    A --> E[logging]
    
    B --> B1[host: 127.0.0.1]
    B --> B2[port: 5030]
    B --> B3[enable_cors: true]
    
    C --> C1[work_dir: ./work]
    C --> C2[pool_size: 10]
    C --> C3[connection_timeout: 30]
    
    D --> D1[data_dir: WeChat Files路径]
    D --> D2[data_key: 预设密钥]
    D --> D3[auto_decrypt: false]
    D --> D4[supported_versions: 3.x, 4.0]
    
    E --> E1[level: info]
    E --> E2[console: true]
    E --> E3[file: logs/app.log]
    
    style A fill:#e3f2fd
    style B fill:#
f8bbd2
    style C fill:#fff3e0
    style D fill:#e8f5e8
    style E fill:#fce4ec
```

## 实现对比

### 重构前 vs 重构后

```mermaid
graph TB
    subgraph "重构前 (问题)"
        A1[main.rs] --> B1[固定日志初始化]
        A1 --> C1[CLI解析]
        C1 --> D1[execute 无上下文]
        D1 --> E1[子命令 无配置访问]
        
        style B1 fill:#ffcdd2
        style D1 fill:#ffcdd2
        style E1 fill:#ffcdd2
    end
    
    subgraph "重构后 (解决方案)"
        A2[main.rs] --> B2[CLI解析]
        B2 --> C2[动态日志初始化]
        B2 --> D2[ExecutionContext创建]
        D2 --> E2[配置文件加载]
        D2 --> F2[execute with context]
        F2 --> G2[子命令 + 配置访问]
        
        style C2 fill:#c8e6c9
        style D2 fill:#c8e6c9
        style E2 fill:#c8e6c9
        style F2 fill:#c8e6c9
        style G2 fill:#c8e6c9
    end
```

## 使用场景示例

### 场景1：使用配置文件
```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Context
    participant Config
    participant KeyCmd
    
    User->>CLI: mwx-cli --config ./config.toml key
    CLI->>Context: new(Some("./config.toml"), "info")
    Context->>Config: load_from_file("./config.toml")
    Config-->>Context: 配置加载成功
    CLI->>KeyCmd: execute(&context)
    KeyCmd->>Context: wechat_data_dir()
    Context-->>KeyCmd: Some("/path/to/wechat/data")
    KeyCmd-->>User: 使用配置的数据目录执行
```

### 场景2：命令行参数覆盖
```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Context
    participant Config
    participant KeyCmd
    
    User->>CLI: mwx-cli --config ./config.toml --log-level debug key
    CLI->>Context: new(Some("./config.toml"), "debug")
    Context->>Config: load_from_file("./config.toml")
    Note over Context: CLI参数 "debug" 覆盖配置文件中的日志级别
    CLI->>KeyCmd: execute(&context)
    KeyCmd->>Context: log_level()
    Context-->>KeyCmd: "debug" (来自CLI参数)
    KeyCmd-->>User: 使用debug级别日志执行
```

## 扩展性设计

```mermaid
graph LR
    A[ExecutionContext] --> B[当前功能]
    A --> C[未来扩展]
    
    B --> B1[配置文件加载]
    B --> B2[日志级别设置]
    B --> B3[微信配置访问]
    
    C --> C1[环境变量支持]
    C --> C2[多配置文件合并]
    C --> C3[运行时配置更新]
    C --> C4[配置文件加密]
    
    style A fill:#e3f2fd
    style B fill:#e8f5e8
    style C fill:#fff3e0
```

---

这
个架构设计确保了：

1. **清晰的职责分离** - 每个组件有明确的职责
2. **灵活的配置管理** - 支持多种配置方式和优先级
3. **统一的上下文传递** - 所有子命令都能访问配置信息
4. **良好的扩展性** - 易于添加新功能和配置选项
5. **完善的错误处理** - 优雅处理各种异常情况

通过这个架构，CLI Options 的实现将更加健壮和用户友好。