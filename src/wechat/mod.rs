//! 微信相关功能模块

pub mod decrypt;
pub mod key;
pub mod process;

use crate::errors::Result;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 微信版本信息
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WeChatVersion {
    /// 3.x版本
    V3x { exact: String },
    /// 4.0版本
    V4x { exact: String },
    /// 企业微信 3.x版本
    V3xW { exact: String},
    /// 企业微信 4.x版本
    V4xW { exact: String},
    /// 未知版本
    Unknown,
}



/// 微信服务
pub struct WeChatService {
    // 占位符实现
}

impl WeChatService {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}