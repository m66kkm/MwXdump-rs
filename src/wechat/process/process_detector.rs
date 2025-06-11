
use crate::wechat::WeChatVersion;
use async_trait::async_trait;
use std::path::PathBuf;
use super::wechat_process_info::WechatProcessInfo;
use crate::errors::Result;

#[cfg(target_os = "windows")]
use super::windows::WindowsProcessDetector as Detector;

#[cfg(target_os = "macos")]
use super::macos::MacOSProcessDetector as Detector;


/// 进程检测器接口
#[async_trait]
pub trait ProcessDetector: Send + Sync {
    /// 检测所有微信进程
    async fn detect_processes(&self) -> Result<Vec<WechatProcessInfo>>;

    // /// 获取指定PID的进程信息
    // async fn get_process_info(&self, pid: u32) -> Result<Option<WechatProcessInfo>>;

    // /// 检测微信版本
    // async fn detect_version(&self, exe_path: &PathBuf) -> Result<WeChatVersion>;

    // /// 定位数据目录
    // async fn locate_data_dir(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>>;
}


/// 创建平台特定的进程检测器
pub fn create_detector() -> Result<Detector> {
    Detector::create_wechat_detector()
}
