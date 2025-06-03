//! 命令行接口模块
//! 
//! 处理所有命令行相关的功能

use clap::{CommandFactory, Parser, Subcommand};
use crate::errors::Result;

pub mod commands;
pub mod context;

use context::ExecutionContext;

/// MwXdump-rs 命令行应用
#[derive(Parser)]
#[command(name = "mwx-cli")]
#[command(about = "微信聊天记录管理工具")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    /// 配置文件路径
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,
    
    /// 日志级别
    #[arg(short, long)]
    pub log_level: Option<String>,
    
    /// 子命令
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// 支持的命令
#[derive(Subcommand)]
pub enum Commands {
    /// 获取微信数据密钥
    Key,

    /// 测试进程检测功能
    Process,

    /// 解密数据文件
    Decrypt {
        /// 加密的数据库文件路径或目录路径
        #[arg(short, long)]
        input: std::path::PathBuf,
        
        /// 解密后的输出文件路径或目录路径
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        
        /// 密钥（十六进制格式，32字节）
        #[arg(short, long)]
        key: String,
        
        /// 指定版本（v3或v4），不指定则自动检测
        #[arg(short, long)]
        version: Option<String>,
        
        /// 仅验证密钥，不进行解密
        #[arg(long)]
        validate_only: bool,
        
        /// 并发处理的线程数，默认为CPU核心数
        #[arg(long, default_value = "0")]
        threads: usize,
    },
    /// 启动HTTP服务器
    // Server,
    
    /// 显示版本信息
    Version,
    
    /// 内存转储（调试用）
    DumpMemory {
        /// 进程ID
        #[arg(short, long)]
        pid: Option<u32>,
    }
}

impl Cli {
    /// 执行命令
    pub async fn execute(self) -> Result<()> {
        // 解构 self 以避免部分移动问题
        let Cli { config, log_level, command } = self;
        
        // 创建执行上下文
        let context = ExecutionContext::new(config, log_level)?;
        
        Self::execute_command_with_context(command, &context).await
    }
    
    /// 使用已有上下文执行命令
    pub async fn execute_with_context(self, context: ExecutionContext) -> Result<()> {
        Self::execute_command_with_context(self.command, &context).await
    }
    
    /// 内部方法：使用上下文执行具体命令
    async fn execute_command_with_context(command: Option<Commands>, context: &ExecutionContext) -> Result<()> {
        match command {
            Some(Commands::Key) => {
                commands::key::execute(context).await
            }

            Some(Commands::Decrypt {
                input,
                output,
                key,
                version,
                validate_only,
                threads
            }) => {
                let args = commands::decrypt::DecryptArgs {
                    input,
                    output,
                    key,
                    version,
                    validate_only,
                    threads,
                };
                commands::decrypt::handle_decrypt(context, args).await
            }
            Some(Commands::Version) => {
                commands::version::execute(context).await
            }
            Some(Commands::DumpMemory { pid }) => {
                commands::dump_memory::execute(context, pid).await
            }
            Some(Commands::Process) => {
                commands::process::execute(context).await
            }
            None => {
                // 没有子命令时显示帮助
                println!("{}", Self::command().render_help());
                Ok(())
            }
        }
    }
}