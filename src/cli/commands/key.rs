//! 测试密钥提取功能命令

use crate::cli::context::ExecutionContext;
use crate::errors::Result;
use crate::wechat::key::{key_extractor, KeyExtractor, WeChatKey};
use crate::wechat::process::{ProcessDetector, create_process_detector};


/// 执行密钥提取测试
pub async fn execute(context: &ExecutionContext) -> Result<()> {
    eprintln!("开始微信密钥提取...");
    
    // 显示当前配置信息
    eprintln!("当前日志级别: {}", context.log_level());
    
    // 如果配置中有预设的数据密钥，显示提示
    if let Some(preset_key) = context.wechat_data_key() {
        println!("检测到配置文件中的预设密钥: {}...", &preset_key[..8.min(preset_key.len())]);
    }
    
    // 如果配置中有数据目录，优先使用
    if let Some(data_dir) = context.wechat_data_dir() {
        println!("使用配置的微信数据目录: {:?}", data_dir);
    }
    
    // 设置更详细的日志级别，确保错误信息被捕获
    tracing::debug!("开始执行密钥提取，日志级别: {}", context.log_level());
    
    // 使用统一方法获取有效的主进程
    let detector = create_process_detector()?;
    
    let valid_main_processes = detector.detect_processes().await?;
    
    if valid_main_processes.is_empty() {
        println!("❌ 未发现有效版本的微信主进程");
        println!("   请确保：");
        println!("   - 微信正在运行");
        println!("   - 微信版本支持密钥提取");
        println!("   - 程序有足够权限访问进程信息");
        return Err(crate::errors::WeChatError::ProcessNotFound.into());
    }

    let key_extractor = key_extractor::create_key_extractor()?;
    // tracing::info!("create key extractor: {}", );

    for process in valid_main_processes.iter() {
        tracing::info!("获取微信进程: {} 的加密密钥", process.pid);
        let key = key_extractor.extract_key(process).await?;
        tracing::info!("密钥获取成功：{}", key);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::context::ExecutionContext;
    
    #[tokio::test]
    async fn test_execute_without_wechat() {
        // 创建测试用的执行上下文
        let context = ExecutionContext::with_defaults(Some("info".to_string()));
        
        // 这个测试在没有微信进程时应该正常完成
        let result = execute(&context).await;
        // 注意：没有微信进程时会返回错误，这是预期的
        assert!(result.is_err());
    }
}