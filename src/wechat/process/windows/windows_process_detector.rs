//! Windows平台的微信进程检测实现

use super::{ProcessDetector, WeChatVersion, WechatProcessInfo};
// use crate::errors::{Result, WeChatError};
use crate::errors::Result;
use crate::utils::windows as utils_windows;
use crate::utils::ProcessInfo;
use async_trait::async_trait;
use chrono::Utc;
use core::time;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use windows::Win32::System::Registry::HKEY_CURRENT_USER;

impl super::WindowsProcessDetector {
    pub fn create_wxwork_detector() -> Result<Self> {
        Ok(Self {
            // 直接克隆 Lazy<Vec> 里的 Vec。这非常高效。
            wechat_process_names: super::WXWORK_PROCESS_NAMES.clone(),
        })
    }

    pub fn create_wechat_detector() -> Result<Self> {
        Ok(Self {
            // .clone() 会隐式地解引用 Lazy，然后调用 Vec::clone()
            wechat_process_names: super::WECHAT_PROCESS_NAMES.clone(),
        })
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

    // 这是一个私有的、同步的、阻塞的辅助方法。
    // 必须保证只在 spawn_blocking 中调用它。
    fn find_wechat_data_directory(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>> {
        // ... (实现和之前一样，无需改动)
        if let Ok(reg_path_str) = utils_windows::registry::get_string_from_registry(
            HKEY_CURRENT_USER,
            super::WECHAT_REG_KEY_PATH,
            super::WECHAT_FILES_VALUE_NAME,
        ) {
            let data_dir = PathBuf::from(reg_path_str);
            if data_dir.is_dir() {
                tracing::info!("PID {}: 通过注册表找到数据目录: {:?}", process.pid, data_dir);
                return Ok(Some(data_dir));
            }
        }

        if let Some(parent) = process.path.parent() {
            let data_dir = parent.join("Data");
            if data_dir.is_dir() {
                tracing::info!("PID {}: 通过进程路径推断找到数据目录: {:?}", process.pid, data_dir);
                return Ok(Some(data_dir));
            }
        }

        tracing::warn!("PID {}: 未能找到微信数据目录", process.pid);
        Ok(None)
    }

}

#[async_trait]
impl ProcessDetector for super::WindowsProcessDetector {
    async fn detect_processes(&self) -> Result<Vec<WechatProcessInfo>> { // &self 依然是 'life0
        tracing::info!("调度阻塞任务：开始检测微信进程...");

        // 我们需要克隆 self 所指向的数据，而不是克隆引用本身。
        // `self` 是 `&WindowsProcessDetector`，所以 `self.clone()` 会调用
        // `WindowsProcessDetector` 的 `Clone` 实现，创建一个全新的实例。
        // `detector` 的类型现在是 `WindowsProcessDetector` (owned value), 不是 `&WindowsProcessDetector`。
        let detector = self.clone(); 

        let detected_processes = tokio::task::spawn_blocking(
            move || -> Result<Vec<WechatProcessInfo>> {
                // `move` 关键字现在移动的是 `detector` 这个拥有所有权的实例，
                // 它的生命周期是 'static，因为它不依赖任何外部引用。
                
                // ... (闭包内部的其他代码保持不变) ...
                let processes = utils_windows::process::list_processes(&detector.wechat_process_names)?;

                let wechat_processes = processes
                    .into_iter()
                    // ... (iterator chain) ...
                    .filter_map(|p| {
                        match WechatProcessInfo::new(p) {
                            Ok(mut wechat_process) => {
                                if let Ok(Some(data_dir)) = detector.find_wechat_data_directory(&wechat_process) {
                                    wechat_process.data_dir = Some(data_dir);
                                }
                                Some(Ok(wechat_process))
                            }
                            Err(e) => {
                                warn!("创建 WechatProcessInfo 失败: {}", e);
                                None
                            }
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;

                Ok(wechat_processes)
            },
        )
        .await??;

        tracing::info!("阻塞任务完成，成功检测到 {} 个微信主进程", detected_processes.len());
        Ok(detected_processes)
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