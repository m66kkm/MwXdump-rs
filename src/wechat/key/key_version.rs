use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use crate::wechat::process::WechatProcessInfo;
use crate::wechat::WeChatVersion;

/// 密钥版本枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyVersion {
    /// 微信3.x版本密钥
    V3x,
    /// 微信4.0版本密钥
    V40,
}


impl KeyVersion {
    /// 从进程信息推断密钥版本
    pub fn from_process(process: &WechatProcessInfo) -> Self {
        use tracing::{info, warn};

        info!(
            "开始为进程 {} (PID: {}) 推断密钥版本",
            process.name, process.pid
        );
        info!(
            "分析进程版本: 进程名={}, 版本={:?}, 路径={:?}",
            process.name, process.version, process.path
        );

        match &process.version {
            WeChatVersion::V3x { exact } => {
                info!("检测到V3x版本: {}", exact);
                // 验证版本号格式
                if exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.') {
                    KeyVersion::V3x
                } else {
                    warn!("V3x版本号格式无效: {}", exact);
                    KeyVersion::V3x
                }
            }
            WeChatVersion::V4x { exact } => {
                info!("检测到V4.0版本: {}", exact);
                // 验证版本号格式
                if exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.') {
                    KeyVersion::V40
                } else {
                    warn!("V4.0版本号格式无效: {}", exact);
                    KeyVersion::V40
                }
            }
            WeChatVersion::Unknown => {
                // 对于WeChat.exe，如果版本未知，默认推断为V3x
                // 因为大多数WeChat.exe是V3版本
                info!("WeChat.exe版本未知，默认推断为V3x版本");
                KeyVersion::V3x
            }
        }
    }

    /// 获取版本的字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyVersion::V3x => "3.x",
            KeyVersion::V40 => "4.0",
        }
    }
}
