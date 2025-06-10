//! Windows平台的微信进程检测实现

use super::{ProcessDetector, WechatProcessInfo, WeChatVersion};
use crate::errors::{Result, WeChatError};

use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};
use once_cell::sync::Lazy;


pub struct WindowsProcessDetector {
    /// 微信进程名称列表
    wechat_process_names: Vec<String>,
}

impl WindowsProcessDetector {

    pub fn new (&self) -> Result<Self>{
        &self.create_wechat_detector()
    }

    pub fn create_wxwork_detector() -> Result<Self> {
        Ok(Self {
            // 从静态变量转换和创建 Vec<String>
            wechat_process_names: WXWORK_PROCESS_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    pub fn create_wechat_detector() -> Result<Self> {
        Ok(Self {
            // 从静态变量转换和创建 Vec<String>
            wechat_process_names: WECHAT_PROCESS_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }

    fn get_process_list(&self) -> Result<Vec<ProcessInfo>> {

    }

    /// 使用tasklist命令获取进程列表，同时获取路径信息
    async fn get_process_list(&self) -> Result<Vec<(u32, String, String)>> {
        let output = Command::new("tasklist")
            .args(&["/fo", "csv", "/nh"])
            .output()
            .map_err(|_| WeChatError::ProcessNotFound)?;

        if !output.status.success() {
            return Err(WeChatError::ProcessNotFound.into());
        }
        // crate::wechat::process::windows::process_detector::list_processes(WECHAT_PROCESS_NAMES);
        crate::utils::win_process::list_processes(&WECHAT_PROCESS_NAMES);

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();

        for line in output_str.lines() {
            let parts: Vec<&str> = line.split(',').map(|s| s.trim_matches('"')).collect();
            if parts.len() >= 5 {
                if let Ok(pid) = parts[1].parse::<u32>() {
                    let name = parts[0].to_string();

                    if self
                        .wechat_process_names
                        .iter()
                        .any(|wechat_name| name.eq_ignore_ascii_case(wechat_name))
                    {
                        // 对于回退方案，路径需要单独获取
                        processes.push((pid, name, String::new()));
                    }
                }
            }
        }
        Ok(processes)
    }

    /// 定位微信数据目录
    async fn find_data_directory(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>> {
        // 微信数据目录的常见位置
        let possible_dirs = vec![
            // 用户文档目录下的WeChat Files
            dirs::document_dir().map(|d| d.join("WeChat Files")),
            // AppData目录下的Tencent/WeChat
            dirs::data_dir().map(|d| d.join("Tencent").join("WeChat")),
            // 程序安装目录附近
            process.path.parent().map(|p| p.join("Data")),
        ];

        for dir_option in possible_dirs {
            if let Some(dir) = dir_option {
                if dir.exists() && dir.is_dir() {
                    info!("找到微信数据目录: {:?}", dir);
                    return Ok(Some(dir));
                }
            }
        }

        warn!("未找到微信数据目录");
        Ok(None)
    }

    /// 获取 WeChat.exe 主进程（排除子进程）
    pub async fn get_main_wechat_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        let all_processes = self.detect_processes().await?;
        println!("检测到 {} 个微信相关进程", all_processes.len());

        Ok(all_processes
            .into_iter()
            // .filter(|process| process.name.eq_ignore_ascii_case("WeChat.exe") | process.name.eq_ignore_ascii_case("Weixin.exe"))
            .collect())
    }

    /// 验证进程版本是否有效（包含数字和点号，非Unknown）
    pub fn validate_process_version(&self, process: &WechatProcessInfo) -> bool {
        match &process.version {
            WeChatVersion::V3x { exact } | WeChatVersion::V4x { exact } => {
                exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.')
            }
            WeChatVersion::Unknown => false,
        }
    }

    /// 获取有效版本的 WeChat.exe 主进程
    pub async fn get_valid_main_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        tracing::info!("开始获取有效的WeChat.exe主进程...");
        let main_processes = self.get_main_wechat_processes().await?;
        Ok(main_processes
            .into_iter()
            .filter(|p| self.validate_process_version(p))
            .collect())
    }

    /// 获取所有微信进程（包括子进程）- 保持向后兼容
    pub async fn get_all_wechat_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        self.detect_processes().await
    }
}

#[async_trait]
impl ProcessDetector for WindowsProcessDetector {
    async fn detect_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        let mut processes = Vec::new();
        tracing::debug!("开始检测微信进程...");
        let process_list = self.get_process_list().await?;

        tracing::info!("检测到 {} 个微信相关进程", process_list.len());
        
        for (pid, name, path_str) in process_list {
            tracing::info!("发现微信进程: {} (PID: {}), Path: {}", name, pid, path_str);

            // 处理路径
            let path = if path_str.is_empty() {
                // 回退方案：单独获取路径
                match self.get_process_path(pid).await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("无法获取进程路径 PID {}: {}", pid, e);
                        continue;
                    }
                }
            } else {
                PathBuf::from(path_str.trim())
            };

            // 检测版本
            let version = self
                .detect_version_from_path(&path)
                .await
                .unwrap_or(WeChatVersion::Unknown);

            let mut process_info = WechatProcessInfo {
                pid,
                name,
                path,
                version,
                data_dir: None,
                detected_at: Utc::now(),
            };

            // 尝试定位数据目录
            process_info.data_dir = self.find_data_directory(&process_info).await.ok().flatten();

            processes.push(process_info);
        }

        info!("检测到 {} 个微信进程", processes.len());
        Ok(processes)
    }

    async fn get_process_info(&self, pid: u32) -> Result<Option<WechatProcessInfo>> {
        let processes = self.detect_processes().await?;
        Ok(processes.into_iter().find(|p| p.pid == pid))
    }

    async fn detect_version(&self, exe_path: &PathBuf) -> Result<WeChatVersion> {
        self.detect_version_from_path(exe_path).await
    }

    async fn locate_data_dir(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>> {
        self.find_data_directory(process).await
    }
}
