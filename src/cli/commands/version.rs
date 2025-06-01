//! 版本命令实现

use crate::errors::Result;

/// 执行版本命令
pub async fn execute() -> Result<()> {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!("Rust版本微信聊天记录管理工具");
    Ok(())
}