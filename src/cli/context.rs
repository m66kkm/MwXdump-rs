//! CLI执行上下文

use crate::config::{AppConfig, ConfigService};
use crate::errors::Result;
use std::path::Path;

/// CLI执行上下文
#[derive(Debug)]
pub struct ExecutionContext {
    /// 配置服务
    config_service: Option<ConfigService>,
    /// 日志级别
    log_level: String,
    /// 默认配置
    default_config: AppConfig,
}

impl ExecutionContext {
    /// 创建新的执行上下文
    pub fn new(config_path: Option<String>, cli_log_level: Option<String>) -> Result<Self> {
        let config_service = if let Some(path) = config_path {
            match ConfigService::load_from_file(&path) {
                Ok(service) => {
                    println!("✅ 成功加载配置文件: {}", path);
                    Some(service)
                }
                Err(e) => {
                    eprintln!("⚠️  配置文件加载失败: {}", e);
                    eprintln!("   使用默认配置继续执行...");
                    None
                }
            }
        } else {
            None
        };
        
        // 确定最终的日志级别：CLI参数 > 配置文件 > 默认值
        let log_level = if let Some(cli_level) = cli_log_level {
            // 用户明确指定了CLI参数，使用CLI参数
            cli_level
        } else if let Some(ref config_service) = config_service {
            // 没有CLI参数但有配置文件，使用配置文件中的日志级别
            config_service.config().logging.level.clone()
        } else {
            // 既没有CLI参数也没有配置文件，使用默认值
            "info".to_string()
        };
        
        Ok(Self {
            config_service,
            log_level,
            default_config: AppConfig::default(),
        })
    }
    
    /// 使用默认配置创建上下文
    pub fn with_defaults(cli_log_level: Option<String>) -> Self {
        let log_level = cli_log_level.unwrap_or_else(|| "info".to_string());
        Self {
            config_service: None,
            log_level,
            default_config: AppConfig::default(),
        }
    }
    
    /// 获取配置
    pub fn config(&self) -> &AppConfig {
        self.config_service
            .as_ref()
            .map(|cs| cs.config())
            .unwrap_or(&self.default_config)
    }
    
    /// 获取日志级别
    pub fn log_level(&self) -> &str {
        &self.log_level
    }
    
    /// 获取微信数据目录
    pub fn wechat_data_dir(&self) -> Option<&Path> {
        self.config().wechat.data_dir.as_deref()
    }
    
    /// 获取微信数据密钥
    pub fn wechat_data_key(&self) -> Option<&str> {
        self.config().wechat.data_key.as_deref()
    }
    
    /// 获取HTTP服务配置
    pub fn http_config(&self) -> &crate::config::HttpConfig {
        &self.config().http
    }
    
    /// 获取数据库配置
    pub fn database_config(&self) -> &crate::config::DatabaseConfig {
        &self.config().database
    }
    
    /// 获取日志配置
    pub fn logging_config(&self) -> &crate::config::LoggingConfig {
        &self.config().logging
    }
    
    /// 检查是否启用自动解密
    pub fn is_auto_decrypt_enabled(&self) -> bool {
        self.config().wechat.auto_decrypt
    }
    
    /// 获取支持的微信版本列表
    pub fn supported_wechat_versions(&self) -> &[String] {
        &self.config().wechat.supported_versions
    }
}