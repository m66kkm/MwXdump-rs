//! 测试密钥提取功能命令

use crate::cli::context::ExecutionContext;
use crate::errors::Result;
use crate::wechat::key::{key_extractor, KeyExtractor, WeChatKey};
use crate::wechat::process::{ProcessDetector, create_detector};


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
    let detector = create_detector()?;
    
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
    
    // let mut success_count = 0;
    // let mut total_count = 0;
    
    // for process in valid_main_processes.iter() {
    //     total_count += 1;
    //     println!("\n🔍 正在处理WeChat.exe主进程 (PID: {})", process.pid);
    //     println!("   进程路径: {:?}", process.path);
    //     println!("   检测到的版本: {:?}", process.version);
    //     println!("   ✅ 版本已验证有效，开始密钥提取");
        
    //     // 根据进程版本创建密钥提取器
    //     let key_version = wechat::key::KeyVersion::from_process(process);
    //     println!("   推断的密钥版本: {:?}", key_version);
        
    //     match wechat::key::create_key_extractor(key_version) {
    //         Ok(extractor) => {
    //             println!("   ✅ 密钥提取器创建成功");
                
    //             // 尝试提取密钥
    //             match extractor.extract_key(process).await {
    //                 Ok(key) => {
    //                     success_count += 1;
    //                     println!("   🎉 成功提取密钥!");
    //                     println!("      密钥: {}", key.to_hex());
    //                     println!("      版本: {:?}", key.version);
    //                     println!("      提取时间: {}", key.extracted_at.format("%Y-%m-%d %H:%M:%S"));
                        
    //                     // 验证密钥
    //                     match extractor.validate_key(&key.key_data).await {
    //                         Ok(true) => {
    //                             println!("      ✅ 密钥验证通过");
    //                         }
    //                         Ok(false) => {
    //                             println!("      ⚠️  密钥验证失败");
    //                         }
    //                         Err(e) => {
    //                             println!("      ⚠️  密钥验证出错: {}", e);
    //                         }
    //                     }
                        
    //                     // 成功提取密钥后停止处理其他进程
    //                     println!("   🎯 已成功提取密钥，停止处理其他进程");
    //                     break;
    //                 }
    //                 Err(e) => {
    //                     println!("   ⚠️  密钥提取失败: {}", e);
                        
    //                     // 提供更详细的失败原因分析
    //                     if e.to_string().contains("不应使用") {
    //                         println!("      💡 提示: 版本不匹配，算法选择可能有误");
    //                     } else if e.to_string().contains("WeChatWin.dll") {
    //                         println!("      💡 提示: V3版本需要WeChatWin.dll模块");
    //                     } else if e.to_string().contains("私有内存") {
    //                         println!("      💡 提示: V4版本需要访问私有内存区域");
    //                     }
    //                 }
    //             }
    //         }
    //         Err(e) => {
    //             println!("   ❌ 无法创建密钥提取器: {}", e);
    //         }
    //     }
        
    //     // 如果已经找到有效版本并尝试提取（无论成功失败），停止处理其他进程
    //     println!("   📋 已处理有效版本的进程，停止检查其他进程");
    //     break;
    // }
    
    // println!("\n📊 测试结果统计:");
    // println!("   总进程数: {}", total_count);
    // println!("   成功提取: {}", success_count);
    // println!("   成功率: {:.1}%", (success_count as f64 / total_count as f64) * 100.0);
    
    // if success_count > 0 {
    //     println!("✅ 密钥提取功能测试完成，发现有效密钥！");
    // } else {
    //     println!("⚠️  密钥提取功能测试完成，但未能提取到有效密钥");
    //     println!("   这可能是由于:");
    //     println!("   - 进程权限不足 (请尝试以管理员身份运行)");
    //     println!("   - 微信版本不支持");
    //     println!("   - 内存搜索算法需要优化");
    //     return Err(crate::errors::WeChatError::KeyExtractionFailed("未能提取到有效密钥".to_string()).into());
    // }
    
    Ok(())
}

// 这个函数已经不需要了，因为错误处理已经移到main.rs中

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