use crate::cli::context::ExecutionContext;
use crate::errors::Result;

/// 执行版本命令
pub async fn execute(context: &ExecutionContext) -> Result<()> {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!("Rust版本微信聊天记录管理工具");
    println!("当前日志级别: {}", context.log_level());
    
    // 显示配置信息
    let config = context.config();
    println!("配置信息:");
    println!("  HTTP服务: {}:{}", config.http.host, config.http.port);
    println!("  工作目录: {:?}", config.database.work_dir);
    if let Some(data_dir) = context.wechat_data_dir() {
        println!("  微信数据目录: {:?}", data_dir);
    }
    
    Ok(())
}