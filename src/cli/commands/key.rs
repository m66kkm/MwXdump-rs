//! 测试密钥提取功能命令

use crate::errors::Result;
use crate::wechat;
use crate::wechat::key::KeyExtractor;
use crate::wechat::process::ProcessDetector;

/// 执行密钥提取测试
pub async fn execute() -> Result<()> {
    println!("开始测试微信密钥提取功能...");
    
    // 设置更详细的日志级别，确保错误信息被捕获
    tracing::debug!("开始执行密钥提取测试");
    
    // 首先检测进程
    let detector = wechat::process::PlatformDetector::new()?;
    let processes = detector.detect_processes().await?;
    
    if processes.is_empty() {
        println!("❌ 未发现运行中的微信进程，无法测试密钥提取");
        return Err(crate::errors::WeChatError::ProcessNotFound.into());
    }
    
    println!("发现 {} 个微信进程，开始提取密钥...", processes.len());
    
    let mut success_count = 0;
    let mut total_count = 0;
    
    // 只处理WeChat.exe主进程，忽略WeChatAppEx.exe子进程
    let wechat_main_processes: Vec<_> = processes.iter()
        .filter(|process| process.name.eq_ignore_ascii_case("WeChat.exe"))
        .collect();
    
    if wechat_main_processes.is_empty() {
        println!("❌ 未发现WeChat.exe主进程");
        return Err(crate::errors::WeChatError::ProcessNotFound.into());
    }
    
    println!("发现 {} 个WeChat.exe主进程，开始提取密钥...", wechat_main_processes.len());
    
    for process in wechat_main_processes.iter() {
        total_count += 1;
        println!("\n🔍 正在处理WeChat.exe主进程 (PID: {})", process.pid);
        println!("   进程路径: {:?}", process.path);
        println!("   检测到的版本: {:?}", process.version);
        
        // 检查版本是否有效（不是Unknown且有具体版本号）
        let has_valid_version = match &process.version {
            wechat::process::WeChatVersion::V3x { exact } => {
                // 检查是否是真实的版本号（包含数字和点）
                exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.')
            },
            wechat::process::WeChatVersion::V40 { exact } => {
                // 检查是否是真实的版本号（包含数字和点）
                exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.')
            },
            wechat::process::WeChatVersion::Unknown => false,
        };
        
        if has_valid_version {
            println!("   ✅ 发现有效版本，将使用此进程进行密钥提取");
        } else {
            println!("   ⚠️  版本信息无效，跳过此进程");
            continue;
        }
        
        // 根据进程版本创建密钥提取器
        let key_version = wechat::key::KeyVersion::from_process(process);
        println!("   推断的密钥版本: {:?}", key_version);
        
        // 显示算法选择逻辑
        match key_version {
            wechat::key::KeyVersion::V3x => {
                println!("   🔧 将使用V3算法 (搜索WeChatWin.dll模块)");
            }
            wechat::key::KeyVersion::V40 => {
                println!("   🔧 将使用V4算法 (搜索私有内存区域)");
            }
        }
        
        match wechat::key::create_key_extractor(key_version) {
            Ok(extractor) => {
                println!("   ✅ 密钥提取器创建成功");
                
                // 尝试提取密钥
                match extractor.extract_key(process).await {
                    Ok(key) => {
                        success_count += 1;
                        println!("   🎉 成功提取密钥!");
                        println!("      密钥: {}", key.to_hex());
                        println!("      版本: {:?}", key.version);
                        println!("      提取时间: {}", key.extracted_at.format("%Y-%m-%d %H:%M:%S"));
                        
                        // 验证密钥
                        match extractor.validate_key(&key.key_data).await {
                            Ok(true) => {
                                println!("      ✅ 密钥验证通过");
                            }
                            Ok(false) => {
                                println!("      ⚠️  密钥验证失败");
                            }
                            Err(e) => {
                                println!("      ⚠️  密钥验证出错: {}", e);
                            }
                        }
                        
                        // 成功提取密钥后停止处理其他进程
                        println!("   🎯 已成功提取密钥，停止处理其他进程");
                        break;
                    }
                    Err(e) => {
                        println!("   ⚠️  密钥提取失败: {}", e);
                        
                        // 提供更详细的失败原因分析
                        if e.to_string().contains("不应使用") {
                            println!("      💡 提示: 版本不匹配，算法选择可能有误");
                        } else if e.to_string().contains("WeChatWin.dll") {
                            println!("      💡 提示: V3版本需要WeChatWin.dll模块");
                        } else if e.to_string().contains("私有内存") {
                            println!("      💡 提示: V4版本需要访问私有内存区域");
                        }
                    }
                }
            }
            Err(e) => {
                println!("   ❌ 无法创建密钥提取器: {}", e);
            }
        }
        
        // 如果已经找到有效版本并尝试提取（无论成功失败），停止处理其他进程
        println!("   📋 已处理有效版本的进程，停止检查其他进程");
        break;
    }
    
    println!("\n📊 测试结果统计:");
    println!("   总进程数: {}", total_count);
    println!("   成功提取: {}", success_count);
    println!("   成功率: {:.1}%", (success_count as f64 / total_count as f64) * 100.0);
    
    if success_count > 0 {
        println!("✅ 密钥提取功能测试完成，发现有效密钥！");
    } else {
        println!("⚠️  密钥提取功能测试完成，但未能提取到有效密钥");
        println!("   这可能是由于:");
        println!("   - 进程权限不足 (请尝试以管理员身份运行)");
        println!("   - 微信版本不支持");
        println!("   - 内存搜索算法需要优化");
        return Err(crate::errors::WeChatError::KeyExtractionFailed("未能提取到有效密钥".to_string()).into());
    }
    
    Ok(())
}

// 这个函数已经不需要了，因为错误处理已经移到main.rs中

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_execute_without_wechat() {
        // 这个测试在没有微信进程时应该正常完成
        let result = execute().await;
        assert!(result.is_ok());
    }
}