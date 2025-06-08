//! 这是一个用于管理和分析微信聊天记录的工具，支持：
//! - 从本地数据库提取聊天记录
//! - 解密微信数据文件
//! - 提供HTTP API服务
//! - 支持MCP协议集成AI助手
//! - Terminal UI界面

pub mod app;
pub mod cli;
pub mod config;
pub mod database;
pub mod errors;
pub mod http;
pub mod mcp;
pub mod models;
pub mod ui;
pub mod wechat;

// 重新导出常用类型
pub use errors::{MwxDumpError, Result};
pub use models::{Message, Contact, ChatRoom, Session};

/// 应用版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");