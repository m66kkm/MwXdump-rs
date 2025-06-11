use clap::Parser;
use tracing::{info, error};
use crate::errors::Result;

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
mod utils;

use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    // 解析命令行参数
    let cli = Cli::parse();
    
    // 创建执行上下文以确定最终的日志级别
    let context = match cli::context::ExecutionContext::new(cli.config.clone(), cli.log_level.clone()) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("创建执行上下文失败: {}", e);
            std::process::exit(1);
        }
    };
    
    // 根据配置初始化日志系统
    init_tracing(&context)?;
    
    info!("MwXdump 启动，日志级别: {}", context.log_level());
    
    // 执行命令，传递已创建的上下文
    if let Err(e) = cli.execute_with_context(context).await {
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

fn init_tracing(context: &cli::context::ExecutionContext) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt};
    use std::fs;
    
    let logging_config = context.logging_config();
    let env_filter = format!("{}={}", context.log_level(), context.log_level());
    
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| context.log_level().into());
    
    let registry = tracing_subscriber::registry().with(filter);
    
    // 根据配置决定输出方式
    match (&logging_config.console, &logging_config.file) {
        (true, Some(log_file_path)) => {
            // 同时输出到控制台和文件
            if let Some(parent_dir) = log_file_path.parent() {
                fs::create_dir_all(parent_dir).map_err(|e| {
                    anyhow::anyhow!("创建日志目录失败: {}", e)
                })?;
            }
            
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(log_file_path)
                .map_err(|e| anyhow::anyhow!("打开日志文件失败: {}", e))?;
            
            registry
                .with(fmt::layer().with_target(false))
                .with(fmt::layer().with_writer(file).with_target(true))
                .init();
        }
        (true, None) => {
            // 仅输出到控制台
            registry
                .with(fmt::layer().with_target(false))
                .init();
        }
        (false, Some(log_file_path)) => {
            // 仅输出到文件
            if let Some(parent_dir) = log_file_path.parent() {
                fs::create_dir_all(parent_dir).map_err(|e| {
                    anyhow::anyhow!("创建日志目录失败: {}", e)
                })?;
            }
            
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(log_file_path)
                .map_err(|e| anyhow::anyhow!("打开日志文件失败: {}", e))?;
            
            registry
                .with(fmt::layer().with_writer(file).with_target(true))
                .init();
        }
        (false, None) => {
            // 默认输出到控制台
            registry
                .with(fmt::layer().with_target(false))
                .init();
        }
    }
    
    Ok(())
}