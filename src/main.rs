use anyhow::Result;
use clap::Parser;
use tracing::{info, error};

mod app;
mod cli;
mod config;
mod database;
mod errors;
mod http;
mod mcp;
mod models;
mod ui;
mod wechat;
mod wechatdb;

use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    init_tracing()?;
    
    info!("MwXdump 启动");
    
    // 解析命令行参数
    let cli = Cli::parse();
    
    // 执行命令
    if let Err(e) = cli.execute().await {
        error!("执行失败: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}

fn init_tracing() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "MwXdump=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    
    Ok(())
}