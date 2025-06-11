//! Windows平台的微信进程检测实现

use super::{ProcessDetector, WechatProcessInfo, WeChatVersion};
// use crate::errors::{Result, WeChatError};
use crate::errors::Result;
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use crate::utils::ProcessInfo;
use crate::utils::windows as utils_windows;
use windows::Win32::System::Registry::HKEY_CURRENT_USER;


impl super::WindowsProcessDetector {
    pub fn create_wxwork_detector() -> Result<Self> {
        Ok(Self {
            // 从静态变量转换和创建 Vec<String>
            wechat_process_names: super::WXWORK_PROCESS_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    pub fn create_wechat_detector() -> Result<Self> {
        Ok(Self {
            // 从静态变量转换和创建 Vec<String>
            wechat_process_names: super::WECHAT_PROCESS_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    fn get_process_list(&self) -> Result<Vec<ProcessInfo>> {
        utils_windows::process::list_processes(&super::WECHAT_PROCESS_NAMES)
    }

    fn find_wechat_data_directory(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>> {
        let data_dir = utils_windows::registry::get_string_from_registry( 
            HKEY_CURRENT_USER, 
            super::WECHAT_REG_KEY_PATH,
            super::WECHAT_FILES_VALUE_NAME);

        if let Some(parent) = process.path.parent() {
            let data_dir = parent.join("Data");
            if data_dir.exists() && data_dir.is_dir() {
                info!("找到微信数据目录: {:?}", data_dir);
                return Ok(Some(data_dir));
            }
        }
        warn!("未找到微信数据目录");
        Ok(None)
    }

    /// 获取 WeChat.exe 主进程（排除子进程）
    async fn get_main_wechat_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        let all_processes = self.detect_processes().await?;
        println!("检测到 {} 个微信相关进程", all_processes.len());

        Ok(all_processes
            .into_iter()
            // .filter(|process| process.name.eq_ignore_ascii_case("WeChat.exe") | process.name.eq_ignore_ascii_case("Weixin.exe"))
            .collect())
    }

    /// 验证进程版本是否有效（包含数字和点号，非Unknown）
    fn validate_process_version(&self, process: &WechatProcessInfo) -> bool {
        match &process.version {
            WeChatVersion::V3x { exact } | WeChatVersion::V4x { exact } => {
                exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.')
            }
            WeChatVersion::Unknown => false,
        }
    }

    /// 获取有效版本的 WeChat.exe 主进程
    async fn get_valid_main_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        tracing::info!("开始获取有效的WeChat.exe主进程...");
        let main_processes = self.get_main_wechat_processes().await?;
        Ok(main_processes
            .into_iter()
            .filter(|p: &WechatProcessInfo| self.validate_process_version(p))
            .collect())
    }



}

#[async_trait]
impl ProcessDetector for super::WindowsProcessDetector {
    async fn detect_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        let mut processes = Vec::new();
        tracing::debug!("开始检测微信进程...");
        let process_list = self.get_process_list()?;

        tracing::info!("检测到 {} 个微信相关进程", process_list.len());

        Ok(processes)
    }

    // async fn get_process_info(&self, pid: u32) -> Result<Option<WechatProcessInfo>> {
    //     let processes = self.detect_processes().await?;
    //     Ok(processes.into_iter().find(|p| p.pid == pid))
    // }

    // async fn detect_version(&self, exe_path: &PathBuf) -> Result<WeChatVersion> {
    //     self.detect_version_from_path(exe_path).await
    // }

    // async fn locate_data_dir(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>> {
    //     self.find_data_directory(process).await
    // }
}
