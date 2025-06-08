//! 微信进程检测模块

use crate::errors::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::wechat::WeChatVersion;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "macos")]
mod macos;

/// 进程信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// 进程ID
    pub pid: u32,
    /// 进程名称
    pub name: String,
    /// 可执行文件路径
    pub path: PathBuf,
    /// 微信版本
    pub version: WeChatVersion,
    /// 数据目录
    pub data_dir: Option<PathBuf>,
    /// 检测时间
    pub detected_at: DateTime<Utc>,
}

/// 进程检测器接口
#[async_trait]
pub trait ProcessDetector: Send + Sync {
    /// 检测所有微信进程
    async fn detect_processes(&self) -> Result<Vec<ProcessInfo>>;
    
    /// 获取指定PID的进程信息
    async fn get_process_info(&self, pid: u32) -> Result<Option<ProcessInfo>>;
    
    /// 检测微信版本
    async fn detect_version(&self, exe_path: &PathBuf) -> Result<WeChatVersion>;
    
    /// 定位数据目录
    async fn locate_data_dir(&self, process: &ProcessInfo) -> Result<Option<PathBuf>>;
}

/// 平台特定的进程检测器
#[cfg(target_os = "windows")]
pub type PlatformDetector = windows::WindowsProcessDetector;

#[cfg(target_os = "macos")]
pub type PlatformDetector = macos::MacOSProcessDetector;

/// 创建平台特定的进程检测器
pub fn create_detector() -> Result<PlatformDetector> {
    PlatformDetector::new()
}

impl ProcessInfo {
    /// 检查进程是否仍在运行
    pub async fn is_running(&self) -> bool {
        // 简单的进程存在性检查
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("tasklist")
                .args(&["/fi", &format!("PID eq {}", self.pid), "/fo", "csv", "/nh"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                return !output_str.trim().is_empty() && output_str.contains(&self.pid.to_string());
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("ps")
                .args(&["-p", &self.pid.to_string()])
                .output()
            {
                return output.status.success();
            }
        }
        
        false
    }
}

impl WeChatVersion {
    /// 获取版本字符串
    pub fn version_string(&self) -> &str {
        match self {
            WeChatVersion::V3x { exact } => exact,
            WeChatVersion::V4x { exact } => exact,
            WeChatVersion::V3xW { exact } => exact,
            WeChatVersion::V4xW { exact } => exact,            
            WeChatVersion::Unknown => "unknown",
        }
    }
    pub fn is_wechat_work(&self) -> bool {
        matches!(self, WeChatVersion::V3xW { .. }) || matches!(self, WeChatVersion::V4xW { .. }) 
    }
    
    /// 是否为3.x版本
    pub fn is_v3x(&self) -> bool {
        matches!(self, WeChatVersion::V3x { .. })
    }
    
    /// 是否为4.x版本
    pub fn is_v4x(&self) -> bool {
        matches!(self, WeChatVersion::V4x { .. })
    }
}