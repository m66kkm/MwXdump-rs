//! 微信用户信息解析

use crate::errors::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "macos")]
mod macos;


/// 密钥数据结构
#[derive(Clone, Serialize, Deserialize)]
pub struct WeChatKey {
    // 微信账户
    pub account: String,
    // 微信手机号
    pub mobile: String,
    // 微信昵称
    pub nickname: String,
    // 微信注册邮箱
    pub mail: String,
    // 微信账户
    pub wxid: String,
    // 微信离线文件管理目录
    pub wx_user_db_path: PathBuf, 
}

/// 微信个人用户信息提取接口
#[async_trait]
pub trait KeyExtractor: Send + Sync {
    /// 从指定进程中提取密钥
    async fn extract_key(&self, process: &ProcessInfo) -> Result<WeChatKey>;
    
    /// 在内存数据中搜索密钥
    async fn search_key_in_memory(&self, memory: &[u8]) -> Result<Option<Vec<u8>>>;
    
    /// 验证密钥是否有效
    async fn validate_key(&self, key: &[u8]) -> Result<bool>;
    
    /// 获取支持的密钥版本
    fn supported_version(&self) -> KeyVersion;
}
