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
async fn main() -> anyhow::Result<()> {
    // 初始化日志系统
    init_tracing()?;
    
    info!("MwXdump 启动");
    
    // 解析命令行参数
    let cli = Cli::parse();
    
    // 执行命令
    if let Err(e) = cli.execute().await {
        error!("执行失败: {}", e);
        
        // 打印更详细的错误信息到控制台
        eprintln!("\n执行失败: {}", e);
        
        // 将错误转换为anyhow::Error以便获取更多信息
        let err_any = anyhow::anyhow!("{}", e);
        
        // 检查错误源
        if let Some(source) = err_any.source() {
            eprintln!("错误原因: {}", source);
        }
        
        // 如果是微信相关错误，提供更详细的错误信息和解决方案
        if e.to_string().contains("微信进程未找到") {
            eprintln!("详细信息: 未找到微信进程，请确保微信正在运行");
        } else if e.to_string().contains("密钥提取失败") {
            eprintln!("详细信息: 密钥提取失败，可能原因:");
            eprintln!("  - 权限不足，请尝试以管理员身份运行");
            eprintln!("  - 微信版本不受支持");
            eprintln!("  - 内存搜索算法需要优化");
        } else if e.to_string().contains("权限不足") {
            eprintln!("详细信息: 权限不足，请尝试以管理员身份运行");
        }
        
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