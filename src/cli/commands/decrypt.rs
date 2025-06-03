//! 测试解密功能的命令

use clap::Args;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use tokio::fs;
use tokio::sync::Semaphore;
use futures::stream::{self, StreamExt};

use crate::errors::Result;
use crate::wechat::decrypt::{create_decryptor, DecryptVersion, validator::KeyValidator};

/// 测试解密功能
#[derive(Args)]
pub struct DecryptArgs {
    /// 加密的数据库文件路径或目录路径
    /// 如果是文件，则解密单个文件
    /// 如果是目录，则递归解密目录中的所有文件
    #[arg(short, long)]
    pub input: PathBuf,
    
    /// 解密后的输出文件路径或目录路径
    /// 单文件模式：可选，默认在原文件同目录生成"des"前缀文件
    /// 目录模式：必需，指定输出目录，保持原目录结构
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    
    /// 密钥（十六进制格式，32字节）
    #[arg(short, long)]
    pub key: String,
    
    /// 指定版本（v3或v4），不指定则自动检测
    #[arg(short, long)]
    pub version: Option<String>,
    
    /// 仅验证密钥，不进行解密
    #[arg(long)]
    pub validate_only: bool,
    
    /// 并发处理的线程数，默认为CPU核心数
    #[arg(long, default_value = "0")]
    pub threads: usize,
}

pub async fn handle_decrypt(context: &crate::cli::context::ExecutionContext, args: DecryptArgs) -> Result<()> {
    info!("🔓 开始测试解密功能");
    info!("当前日志级别: {}", context.log_level());
    
    // 显示配置信息
    if let Some(data_dir) = context.wechat_data_dir() {
        info!("配置的微信数据目录: {:?}", data_dir);
    }
    
    if let Some(_preset_key) = context.wechat_data_key() {
        info!("检测到配置文件中的预设密钥");
        // 如果命令行没有提供密钥，可以使用配置文件中的密钥
        if args.key.is_empty() {
            info!("使用配置文件中的预设密钥");
            // 这里可以扩展逻辑来使用预设密钥
        }
    }
    
    // 解析密钥
    let key_bytes = hex::decode(&args.key)
        .map_err(|e| crate::errors::WeChatError::DecryptionFailed(format!("密钥格式错误: {}", e)))?;
    
    if key_bytes.len() != 32 {
        return Err(crate::errors::WeChatError::DecryptionFailed(
            format!("密钥长度错误: {} 字节，期望 32 字节", key_bytes.len())
        ).into());
    }
    
    info!("✅ 密钥解析成功: {} 字节", key_bytes.len());
    
    // 检查输入路径
    if !args.input.exists() {
        return Err(crate::errors::WeChatError::DecryptionFailed(
            format!("输入路径不存在: {:?}", args.input)
        ).into());
    }
    
    // 判断是文件还是目录
    if args.input.is_file() {
        // 单文件解密
        handle_single_file_decrypt(&args, &key_bytes).await
    } else if args.input.is_dir() {
        // 目录批量解密
        handle_directory_decrypt(&args, &key_bytes).await
    } else {
        Err(crate::errors::WeChatError::DecryptionFailed(
            format!("输入路径既不是文件也不是目录: {:?}", args.input)
        ).into())
    }
}

/// 处理单文件解密
async fn handle_single_file_decrypt(args: &DecryptArgs, key_bytes: &[u8]) -> Result<()> {
    info!("📁 单文件解密模式: {:?}", args.input);
    
    // 创建密钥验证器
    let validator = KeyValidator::new();
    
    // 确定版本
    let version = determine_version(args, &validator, &args.input, key_bytes).await?;
    
    // 如果只是验证密钥
    if args.validate_only {
        info!("✅ 密钥验证成功！");
        return Ok(());
    }
    
    // 确定输出文件路径
    let output_path = args.output.clone().unwrap_or_else(|| {
        let mut path = args.input.clone();
        if let Some(stem) = path.file_stem() {
            let mut new_name = "des".to_string();
            new_name.push_str(&stem.to_string_lossy());
            if let Some(ext) = path.extension() {
                new_name.push('.');
                new_name.push_str(&ext.to_string_lossy());
            }
            path.set_file_name(new_name);
        }
        path
    });
    
    // 执行单文件解密
    decrypt_single_file(&args.input, &output_path, key_bytes, version).await
}

/// 处理目录批量解密
async fn handle_directory_decrypt(args: &DecryptArgs, key_bytes: &[u8]) -> Result<()> {
    info!("📁 目录批量解密模式: {:?}", args.input);
    
    // 输出目录必须指定
    let output_dir = match &args.output {
        Some(output) => output.clone(),
        None => {
            return Err(crate::errors::WeChatError::DecryptionFailed(
                "目录解密模式下必须指定输出目录 (-o 参数)".to_string()
            ).into());
        }
    };
    
    // 确保输出目录存在
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir).await?;
        info!("📁 创建输出目录: {:?}", output_dir);
    }
    
    if !output_dir.is_dir() {
        return Err(crate::errors::WeChatError::DecryptionFailed(
            format!("输出路径不是目录: {:?}", output_dir)
        ).into());
    }
    
    // 递归收集所有文件
    let files = collect_files_recursively(args.input.clone()).await?;
    info!("📊 发现 {} 个文件待处理", files.len());
    
    if args.validate_only {
        info!("✅ 仅验证模式，跳过实际解密");
        return Ok(());
    }
    
    // 确定并发数
    let thread_count = if args.threads == 0 {
        num_cpus::get()
    } else {
        args.threads
    };
    
    info!("🚀 使用 {} 个并发线程处理文件", thread_count);
    
    // 创建信号量来限制并发数
    let semaphore = Arc::new(Semaphore::new(thread_count));
    
    // 统计信息
    let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start_time = std::time::Instant::now();
    
    // 并行处理文件
    let _results = stream::iter(files.iter().enumerate())
        .map(|(index, file_path)| {
            let semaphore = semaphore.clone();
            let success_count = success_count.clone();
            let failed_count = failed_count.clone();
            let output_dir = output_dir.clone();
            let args_input = args.input.clone();
            let key_bytes = key_bytes.to_vec();
            let file_path = file_path.clone();
            let total_files = files.len();
            let args_clone = DecryptArgs {
                input: args.input.clone(),
                output: args.output.clone(),
                key: args.key.clone(),
                version: args.version.clone(),
                validate_only: args.validate_only,
                threads: args.threads,
            };
            
            async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                info!("📄 处理文件 {}/{}: {:?}", index + 1, total_files, file_path);
                
                // 计算相对路径
                let relative_path = match file_path.strip_prefix(&args_input) {
                    Ok(path) => path,
                    Err(e) => {
                        let error_msg = format!("计算相对路径失败: {}", e);
                        warn!("⚠️  解密失败: {:?} - {}", file_path, error_msg);
                        failed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                };
                
                // 构建输出路径
                let mut output_file = output_dir.join(relative_path);
                
                // 修改文件名添加"des"前缀
                if let Some(file_name) = output_file.file_name() {
                    let new_name = format!("des{}", file_name.to_string_lossy());
                    output_file.set_file_name(new_name);
                }
                
                // 确保输出目录存在
                if let Some(parent) = output_file.parent() {
                    if !parent.exists() {
                        if let Err(e) = fs::create_dir_all(parent).await {
                            warn!("⚠️  创建目录失败: {:?} - {}", parent, e);
                            failed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    }
                }
                
                // 尝试解密文件
                match decrypt_file_with_auto_version_parallel(&file_path, &output_file, &key_bytes, &args_clone).await {
                    Ok(_) => {
                        success_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        info!("✅ 解密成功: {:?} -> {:?}", file_path, output_file);
                    }
                    Err(e) => {
                        failed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!("⚠️  解密失败: {:?} - {}", file_path, e);
                    }
                }
            }
        })
        .buffer_unordered(thread_count)
        .collect::<Vec<_>>()
        .await;
    
    let elapsed = start_time.elapsed();
    let final_success_count = success_count.load(std::sync::atomic::Ordering::Relaxed);
    let final_failed_count = failed_count.load(std::sync::atomic::Ordering::Relaxed);
    
    // 输出统计信息
    info!("🎉 并行批量解密完成！");
    info!("🚀 使用线程数: {}", thread_count);
    info!("📊 总文件数: {}", files.len());
    info!("✅ 成功: {}", final_success_count);
    info!("❌ 失败: {}", final_failed_count);
    info!("⏱️  总耗时: {:.2} 秒", elapsed.as_secs_f64());
    if elapsed.as_secs_f64() > 0.0 {
        info!("📈 平均速度: {:.2} 文件/秒", files.len() as f64 / elapsed.as_secs_f64());
    }
    info!("📁 输出目录: {:?}", output_dir);
    
    Ok(())
}

/// 确定解密版本
async fn determine_version(
    args: &DecryptArgs,
    validator: &KeyValidator,
    file_path: &PathBuf,
    key_bytes: &[u8],
) -> Result<DecryptVersion> {
    if let Some(version_str) = &args.version {
        match version_str.to_lowercase().as_str() {
            "v3" => Ok(DecryptVersion::V3),
            "v4" => Ok(DecryptVersion::V4),
            _ => Err(crate::errors::WeChatError::DecryptionFailed(
                format!("不支持的版本: {}", version_str)
            ).into()),
        }
    } else {
        // 自动检测版本
        info!("🔍 自动检测版本...");
        match validator.validate_key_auto(file_path, key_bytes).await? {
            Some(detected_version) => {
                info!("✅ 检测到版本: {:?}", detected_version);
                Ok(detected_version)
            }
            None => {
                error!("❌ 密钥验证失败，无法确定版本");
                Err(crate::errors::WeChatError::DecryptionFailed(
                    "密钥验证失败".to_string()
                ).into())
            }
        }
    }
}

/// 递归收集目录中的所有.db文件
fn collect_files_recursively(dir: PathBuf) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PathBuf>>> + Send>> {
    Box::pin(async move {
        let mut files = Vec::new();
        let mut entries = fs::read_dir(&dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() {
                // 只收集.db文件
                if let Some(ext) = path.extension() {
                    if ext.to_string_lossy().to_lowercase() == "db" {
                        files.push(path);
                    }
                }
            } else if path.is_dir() {
                // 递归处理子目录
                let mut sub_files = collect_files_recursively(path).await?;
                files.append(&mut sub_files);
            }
        }
        
        Ok(files)
    })
}

/// 解密单个文件
async fn decrypt_single_file(
    input_path: &PathBuf,
    output_path: &PathBuf,
    key_bytes: &[u8],
    version: DecryptVersion,
) -> Result<()> {
    info!("📁 输出文件: {:?}", output_path);
    
    // 创建解密器
    let decryptor = create_decryptor(version);
    
    // 执行解密
    info!("🔓 开始解密...");
    
    let start_time = std::time::Instant::now();
    
    // 带进度回调的解密
    let progress_callback = Box::new(|current: u64, total: u64| {
        let percentage = (current as f64 / total as f64) * 100.0;
        if current % 100 == 0 || current == total {
            info!("📊 解密进度: {}/{} ({:.1}%)", current, total, percentage);
        }
    });
    
    decryptor.decrypt_database_with_progress(
        input_path,
        output_path,
        key_bytes,
        Some(progress_callback),
    ).await?;
    
    let elapsed = start_time.elapsed();
    
    info!("🎉 解密完成！");
    info!("⏱️  耗时: {:.2} 秒", elapsed.as_secs_f64());
    
    // 验证输出文件
    verify_output_file(output_path).await?;
    
    Ok(())
}

/// 使用自动版本检测解密文件（并行版本）
async fn decrypt_file_with_auto_version_parallel(
    input_path: &PathBuf,
    output_path: &PathBuf,
    key_bytes: &[u8],
    args: &DecryptArgs,
) -> Result<()> {
    // 检查文件大小，跳过太小的文件
    let metadata = fs::metadata(input_path).await?;
    if metadata.len() < 1024 {  // 小于1KB的文件可能不是有效的数据库
        return Err(crate::errors::WeChatError::DecryptionFailed(
            format!("文件太小，跳过: {:?} ({} 字节)", input_path, metadata.len())
        ).into());
    }
    
    let validator = KeyValidator::new();
    
    // 使用更安全的版本检测
    let version = match determine_version_safe(args, &validator, input_path, key_bytes).await {
        Ok(v) => v,
        Err(e) => {
            return Err(crate::errors::WeChatError::DecryptionFailed(
                format!("版本检测失败: {}", e)
            ).into());
        }
    };
    
    let decryptor = create_decryptor(version);
    
    decryptor.decrypt_database_with_progress(
        input_path,
        output_path,
        key_bytes,
        None, // 并行处理时不显示详细进度
    ).await?;
    
    Ok(())
}

/// 安全的版本检测，带有更好的错误处理
async fn determine_version_safe(
    args: &DecryptArgs,
    validator: &KeyValidator,
    file_path: &PathBuf,
    key_bytes: &[u8],
) -> Result<DecryptVersion> {
    if let Some(version_str) = &args.version {
        match version_str.to_lowercase().as_str() {
            "v3" => Ok(DecryptVersion::V3),
            "v4" => Ok(DecryptVersion::V4),
            _ => Err(crate::errors::WeChatError::DecryptionFailed(
                format!("不支持的版本: {}", version_str)
            ).into()),
        }
    } else {
        // 自动检测版本，使用更安全的方法
        match validator.validate_key_auto(file_path, key_bytes).await {
            Ok(Some(detected_version)) => {
                Ok(detected_version)
            }
            Ok(None) => {
                Err(crate::errors::WeChatError::DecryptionFailed(
                    "密钥验证失败，无法确定版本".to_string()
                ).into())
            }
            Err(e) => {
                Err(crate::errors::WeChatError::DecryptionFailed(
                    format!("版本检测过程出错: {}", e)
                ).into())
            }
        }
    }
}

/// 验证输出文件
async fn verify_output_file(output_path: &PathBuf) -> Result<()> {
    if output_path.exists() {
        let file_size = fs::metadata(output_path).await?.len();
        info!("📊 输出文件大小: {} 字节", file_size);
        
        // 简单验证是否为SQLite文件
        let mut file = fs::File::open(output_path).await?;
        let mut header = [0u8; 16];
        use tokio::io::AsyncReadExt;
        file.read_exact(&mut header).await?;
        
        if header.starts_with(b"SQLite format 3") {
            info!("✅ 输出文件验证成功：有效的SQLite数据库");
        } else {
            warn!("⚠️  输出文件可能不是有效的SQLite数据库");
        }
    } else {
        error!("❌ 输出文件不存在");
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_test_decrypt_args() {
        // 基本的参数解析测试
        let args = DecryptArgs {
            input: PathBuf::from("test.db"),
            output: Some(PathBuf::from("output.db")),
            key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            version: Some("v3".to_string()),
            validate_only: false,
            threads: 4,
        };
        
        assert_eq!(args.input, PathBuf::from("test.db"));
        assert_eq!(args.output, Some(PathBuf::from("output.db")));
        assert_eq!(args.key.len(), 64); // 32字节的十六进制表示
        assert_eq!(args.version, Some("v3".to_string()));
        assert!(!args.validate_only);
        assert_eq!(args.threads, 4);
    }
}