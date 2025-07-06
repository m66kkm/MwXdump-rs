//! 解密功能的命令

use anyhow::Context;
use clap::Args;
use std::path::PathBuf;
use tracing::info;

use crate::cli::context::ExecutionContext;
use crate::errors::{Result, WeChatError};
use crate::wechat::decrypt::DecryptionProcessor;
use crate::wechat::key::key_extractor::{create_key_extractor, KeyExtractor};
use crate::wechat::process::{create_process_detector, ProcessDetector};

/// 自动或手动解密微信数据库文件
#[derive(Args, Debug)]
#[command(long_about = "此命令用于解密微信的数据库文件（通常是 .db 文件）。\n\n它支持两种主要模式：\n1. 自动模式：如果您不提供输入路径和密钥，程序将自动尝试查找正在运行的微信进程，从中提取密钥和数据目录路径，然后进��解密。\n2. 手动模式：您可以明确指定输入文件/目录、输出目录和解密密钥。")]
pub struct DecryptArgs {
    /// [可选] 指定加密的数据库文件路径或包含数据库文件的目录路径。
    /// 如果不提供，程序将自动检测当前用户的微信数据目录。
    #[arg(short, long, help = "要解密的输入文件或目录", long_help = "指定一个或多个加密数据库文件（.db）的路径，或者包含这些文件的整个目录。如果留空，将尝试自动从运行中的微信进程定位数据目录。")]
    pub input: Option<PathBuf>,

    /// [必选] 指定解密后文件的输出目录。
    /// 解密后的文件将保持其在输入目录中的原始相对路径。
    #[arg(short, long, help = "解密文件的输出目录", long_help = "所有成功解密的文件都将存放在此目录下。程序会保留原始的目录结构。这是一个必填参数。")]
    pub output: PathBuf,

    /// [可选] 提供32字节（64个十六进制字符）的解密密钥。
    /// 如果不提供，程序将自动从运行中的微信进程中提取。
    #[arg(short, long, help = "用于解密的16进制密钥", long_help = "提供一个64个字符的十六进制字符串作为解密密钥。如果留空，将尝试自动从运行中的微信进程中提取密钥。")]
    pub key: Option<String>,

    /// [可选] 仅验证密钥有效性，不执行解密过程。
    /// 程序会尝试用提供的或自动获取的密钥去读取数据库文件的头部，以验证密钥是否正确。
    #[arg(long, help = "仅验证密钥，不执行解密", long_help = "如果设置此标志，程序将只检查密钥是否能成功解密数据库的头部信息，而不会写入任何解密后的文件。这对于快速验证密钥非常有用。")]
    pub validate_only: bool,

    /// [可选] 指定并发处理的线程数。
    /// 默认为系统的CPU核心数。
    #[arg(long, help = "设置并发解密的线程数", long_help = "指定用于并行解密文件的线程数量。如果留空或设为0，将自动使用您计算机的CPU核心数作为默认值，以实现最佳性能。")]
    pub threads: Option<usize>,
}

impl DecryptArgs {
    /// 验证参数的有效性
    pub fn validate(&self) -> Result<()> {
        if let Some(input_path) = &self.input {
            if !input_path.exists() {
                return Err(WeChatError::DecryptionFailed(format!(
                    "指定的输入路径不存在: {:?}",
                    input_path
                ))
                .into());
            }
        }
        if let Some(key_str) = &self.key {
            if hex::decode(key_str)
                .map_err(|e| WeChatError::DecryptionFailed(format!("密钥格式错误: {}", e)))?
                .len()
                != 32
            {
                return Err(WeChatError::DecryptionFailed(
                    "密钥长度必须为32字节（64个十六进制字符）".to_string(),
                )
                .into());
            }
        }
        Ok(())
    }
}

/// 执行解密命令
pub async fn execute(context: &ExecutionContext, args: DecryptArgs) -> Result<()> {
    info!("🔓 开始执行解密，参数: {:?}", args);
    args.validate()?;

    // 1. 获取密钥
    let key_bytes = get_key(context, &args).await?;
    info!("✅ 密钥获取成功: {} 字节", key_bytes.len());

    // 2. 获取输入路径
    let input_path = get_input_path(context, &args).await?;
    info!("📁 输入路径确定: {:?}", input_path);

    // 3. 创建解密处理器并执行解密
    let processor = DecryptionProcessor::new(
        input_path,
        args.output,
        key_bytes,
        args.threads,
        args.validate_only,
    );

    processor.execute().await
}

/// 获取密钥，如果用户未提供则自动提取
async fn get_key(context: &ExecutionContext, args: &DecryptArgs) -> Result<Vec<u8>> {
    if let Some(key_str) = &args.key {
        info!("🔑 使用用户提供的密钥");
        return Ok(hex::decode(key_str)?);
    }

    if let Some(preset_key) = context.wechat_data_key() {
        info!("🔑 使用配置文件中的预设密钥");
        return Ok(hex::decode(preset_key)?);
    }

    info!("🔑 自动从微信进程提取密钥...");
    let detector = create_process_detector().context("创建进程检测器失败")?;
    let processes = detector.detect_processes().await.context("检测微信进程失败")?;
    if processes.is_empty() {
        return Err(WeChatError::ProcessNotFound.into());
    }

    let process = &processes[0];
    info!("🎯 目标进程: {} (PID: {})", process.name, process.pid);

    let key_extractor = create_key_extractor().context("创建密钥提取器失败")?;
    let wechat_key = key_extractor.extract_key(process).await.context("提取密钥失败")?;
    info!("🎉 自动提取密钥成功");
    Ok(wechat_key.key_data)
}

/// 获取输入路径，如果用户未提供则自动检测
async fn get_input_path(context: &ExecutionContext, args: &DecryptArgs) -> Result<PathBuf> {
    if let Some(input_path) = &args.input {
        info!("📂 使用用户提供的输入路径");
        return Ok(input_path.clone());
    }

    if let Some(data_dir) = context.wechat_data_dir() {
        info!("📂 使用配置文件中的数据目录");
        return Ok(data_dir.to_path_buf());
    }

    info!("📂 自动检测微信数据目录...");
    let detector = create_process_detector()?;
    let processes = detector.detect_processes().await?;
    if processes.is_empty() {
        return Err(WeChatError::ProcessNotFound.into());
    }

    let process = &processes[0];
    if let Some(data_dir) = &process.data_dir {
        info!("🎉 自动检测到数据目录: {:?}", data_dir);
        Ok(data_dir.to_path_buf())
    } else {
        Err(WeChatError::DecryptionFailed(
            "无法自动确定微信数据目录".to_string(),
        )
        .into())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_args_validation() {
        let args = DecryptArgs {
            input: Some(PathBuf::from("test.db")),
            output: PathBuf::from("output_dir"),
            key: Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            validate_only: false,
            threads: Some(4),
        };
        assert!(args.validate().is_ok());

        let bad_key_args = DecryptArgs {
            key: Some("shortkey".to_string()),
            ..args
        };
        assert!(bad_key_args.validate().is_err());
    }
}