# Chatlog Rust版本

这是微信聊天记录管理工具的Rust实现版本。

## 项目状态

当前处于第一阶段：基础架构搭建阶段

### 已完成
- ✅ 项目结构创建
- ✅ Cargo.toml配置
- ✅ 基础模块框架
- ✅ 错误处理系统
- ✅ 配置管理系统
- ✅ CLI命令框架
- ✅ 基础占位符实现

### 模块结构
```
src/
├── main.rs              # 程序入口
├── lib.rs               # 库入口
├── app/                 # 应用核心逻辑
├── cli/                 # 命令行接口
│   └── commands/        # 各种命令实现
├── config/              # 配置管理
├── database/            # 数据库操作
├── errors/              # 错误处理
├── http/                # HTTP服务
├── mcp/                 # MCP协议实现
├── models/              # 数据模型
├── ui/                  # Terminal UI
├── wechat/              # 微信相关功能
│   ├── decrypt/         # 解密模块
│   ├── key/             # 密钥提取
│   └── process/         # 进程检测
└── wechatdb/            # 微信数据库操作
```

### 支持的命令
- `mwx-cli` - 启动TUI界面
- `mwx-cli key` - 提取微信数据密钥
- `mwx-cli decrypt` - 解密数据文件
- `mwx-cli server` - 启动HTTP服务器
- `mwx-cli version` - 显示版本信息
- `mwx-cli dump-memory` - 内存转储（调试用）

## 构建和运行

```bash
# 编译项目
cargo build

# 运行项目
cargo run

# 运行特定命令
cargo run -- version
cargo run -- key
cargo run -- server --host 127.0.0.1 --port 5030
```

## 下一步计划

根据迁移计划，接下来需要实现：

1. 完善数据模型定义
2. 实现微信进程检测
3. 实现密钥提取功能
4. 实现数据解密功能
5. 实现数据库操作
6. 实现HTTP服务
7. 实现Terminal UI

## 技术栈

- **异步运行时**: tokio
- **Web框架**: axum
- **Terminal UI**: ratatui
- **命令行**: clap
- **数据库**: sqlx (SQLite)
- **序列化**: serde
- **错误处理**: thiserror + anyhow
- **日志**: tracing
- **配置**: config-rs

## 许可证

Apache-2.0