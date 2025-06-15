//! 测试进程检测命令

use anyhow::Context;

use crate::cli::commands::process;
use crate::cli::context::ExecutionContext;
use crate::errors::Result;
use crate::wechat::process::{create_detector, ProcessDetector};
/// 执行进程检测测试
pub async fn execute(context: &ExecutionContext) -> Result<()> {
    tracing::info!("开始测试微信进程检测功能...");

    // 显示配置信息
    if let Some(data_dir) = context.wechat_data_dir() {
        tracing::debug!("配置的微信数据目录: {:?}", data_dir);
    }

    let detector = create_detector().context("初始化检测器失败")?;

    let processes = detector
        .detect_processes()
        .await
        .context("检测微信进程失败")?;

    if processes.is_empty() {
        eprintln!("✅ 进程检测功能正常，但未发现运行中的微信进程");
    } else {
        eprintln!("✅ 检测到 {} 个微信进程:", processes.len());
        for (i, process) in processes.iter().enumerate() {
            eprintln!("  {}. 进程名: {}", i + 1, process.name);
            eprintln!("     PID: {}", process.pid);
            eprintln!("     是否主进程: {}", process.is_main_process);
            eprintln!("     路径: {:?}", process.path);
            eprintln!("     版本: {:?}", process.version);
            
            if let Some(data_dir) = &process.data_dir {
                eprintln!("     数据目录: {:?}", data_dir);
                eprintln!("     微信ID: {}", process.get_current_wxid().unwrap_or("未找到".to_string()));
            
            } else {
                eprintln!("     数据目录: 未找到");
            }
            eprintln!(
                "     检测时间: {}",
                process.detected_at.format("%Y-%m-%d %H:%M:%S")
            );
            eprintln!();
        }
    }
    eprintln!("进程检测测试完成！");
    Ok(())
}
