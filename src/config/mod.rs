//! 配置管理模块
//! 
//! 负责应用配置的加载、验证和管理

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::errors::{ConfigError, Result};

/// 应用主配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// HTTP服务配置
    pub http: HttpConfig,
    
    /// 数据库配置
    pub database: DatabaseConfig,
    
    /// 微信配置
    pub wechat: WeChatConfig,
    
    /// 日志配置
    pub logging: LoggingConfig,
}

/// HTTP服务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// 监听地址
    pub host: String,
    
    /// 监听端口
    pub port: u16,
    
    /// 是否启用CORS
    pub enable_cors: bool,
    
    /// 静态文件目录
    pub static_dir: Option<PathBuf>,
}

/// 数据库配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// 工作目录
    pub work_dir: PathBuf,
    
    /// 连接池大小
    pub pool_size: u32,
    
    /// 连接超时时间（秒）
    pub connection_timeout: u64,
}

/// 微信配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeChatConfig {
    /// 数据目录
    pub data_dir: Option<PathBuf>,
    
    /// 数据密钥
    pub data_key: Option<String>,
    
    /// 是否启用自动解密
    pub auto_decrypt: bool,
    
    /// 支持的微信版本
    pub supported_versions: Vec<String>,
}

/// 日志配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// 日志级别
    pub level: String,
    
    /// 日志文件路径
    pub file: Option<PathBuf>,
    
    /// 是否输出到控制台
    pub console: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            http: HttpConfig {
                host: "127.0.0.1".to_string(),
                port: 5030,
                enable_cors: true,
                static_dir: None,
            },
            database: DatabaseConfig {
                work_dir: PathBuf::from("./work"),
                pool_size: 10,
                connection_timeout: 30,
            },
            wechat: WeChatConfig {
                data_dir: None,
                data_key: None,
                auto_decrypt: false,
                supported_versions: vec![
                    "3.x".to_string(),
                    "4.0".to_string(),
                ],
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
                console: true,
            },
        }
    }
}

impl AppConfig {
    /// 从文件加载配置
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(ConfigError::FileNotFound {
                path: path.display().to_string(),
            }.into());
        }
        
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        
        let config: AppConfig = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// 保存配置到文件
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        
        std::fs::write(path, content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        
        Ok(())
    }
    
    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        // 验证端口范围
        if self.http.port == 0 {
            return Err(ConfigError::InvalidValue {
                key: "http.port".to_string(),
                value: self.http.port.to_string(),
            }.into());
        }
        
        // 验证工作目录
        if !self.database.work_dir.is_absolute() {
            // 如果是相对路径，转换为绝对路径
        }
        
        // 验证日志级别
        match self.logging.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => {
                return Err(ConfigError::InvalidValue {
                    key: "logging.level".to_string(),
                    value: self.logging.level.clone(),
                }.into());
            }
        }
        
        Ok(())
    }
    
    /// 获取HTTP服务地址
    pub fn http_addr(&self) -> String {
        format!("{}:{}", self.http.host, self.http.port)
    }
}

/// 配置服务
pub struct ConfigService {
    config: AppConfig,
    config_path: Option<PathBuf>,
}

impl ConfigService {
    /// 创建新的配置服务
    pub fn new() -> Self {
        Self {
            config: AppConfig::default(),
            config_path: None,
        }
    }
    
    /// 从文件加载配置
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let config = AppConfig::from_file(&path)?;
        
        Ok(Self {
            config,
            config_path: Some(path),
        })
    }
    
    /// 获取配置
    pub fn config(&self) -> &AppConfig {
        &self.config
    }
    
    /// 更新配置
    pub fn update_config<F>(&mut self, f: F) -> Result<()>
    where
        F: FnOnce(&mut AppConfig),
    {
        f(&mut self.config);
        self.config.validate()?;
        
        // 如果有配置文件路径，自动保存
        if let Some(ref path) = self.config_path {
            self.config.save_to_file(path)?;
        }
        
        Ok(())
    }
    
    /// 保存配置
    pub fn save(&self) -> Result<()> {
        if let Some(ref path) = self.config_path {
            self.config.save_to_file(path)
        } else {
            Err(ConfigError::ParseError("No config file path set".to_string()).into())
        }
    }
}