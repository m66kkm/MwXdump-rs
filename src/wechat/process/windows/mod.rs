//! Windows平台的微信进程检测实现

use super::{ProcessDetector, ProcessInfo, WeChatVersion};
use crate::errors::{Result, WeChatError};

use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};

const WECHAT_REG_KEY_PATH: &str = "Software\\Tencent\\WeChat";
const WECHAT_FILES_VALUE_NAME: &str = "FileSavePath";
const WECHAT_PROCESS_NAMES: &[&str] = &[
    "WeChat.exe",
    "Weixin.exe", // 微信4.0的主可执行文件名
    "WeChatApp.exe",
    // "WXWork.exe", // 企业微信
    // "WeChatAppEx.exe", // 微信增强版
];

// const WECHAT_REG_KEY_PATH: &str = "Software\\Tencent\\WeChat";
// const WECHAT_FILES_VALUE_NAME: &str = "FileSavePath";
// const WECHAT_PROCESS_NAMES: &[&str] = &[
//     "WeChat.exe",
//     "Weixin.exe", // 微信4.0的主可执行文件名
//     "WeChatApp.exe",
//     // "WXWork.exe", // 企业微信
//     // "WeChatAppEx.exe", // 微信增强版
// ];

pub struct WindowsProcessDetector {
    /// 微信进程名称列表
    wechat_process_names: Vec<String>,
}

impl WindowsProcessDetector {
    /// 创建新的Windows进程检测器
    pub fn new() -> Result<Self> {
        Ok(Self {
            wechat_process_names: vec![
                "WeChat.exe".to_string(),
                "Weixin.exe".to_string(), // 添加微信4.0的主可执行文件名
                "WeChatApp.exe".to_string(),
                // "WXWork.exe".to_string(),
                // "WeChatAppEx.exe".to_string(),
            ],
        })
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
        crate::utils::win_process_detector::list_processes(
            WECHAT_PROCESS_NAMES,
        );
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

    /// 使用wmic命令获取进程的可执行文件路径
    async fn get_process_path(&self, pid: u32) -> Result<PathBuf> {
        if let Ok(reg_path) = crate::utils::win_registry::get_string_from_registry(
            windows::Win32::System::Registry::HKEY_CURRENT_USER,
            WECHAT_REG_KEY_PATH,
            WECHAT_FILES_VALUE_NAME,
        ) {
            tracing::info!("从注册表获取到路径: {}", reg_path);
        }

        let output = Command::new("wmic")
            .args(&[
                "process",
                "where",
                &format!("ProcessId={}", pid),
                "get",
                "ExecutablePath",
                "/format:list",
            ])
            .output()
            .map_err(|_| WeChatError::ProcessNotFound)?;

        if !output.status.success() {
            return Err(WeChatError::ProcessNotFound.into());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        debug!("wmic输出: {}", output_str);

        for line in output_str.lines() {
            let line = line.trim();
            if line.starts_with("ExecutablePath=") {
                let path = line.strip_prefix("ExecutablePath=").unwrap_or("").trim();
                if !path.is_empty() {
                    debug!("解析到路径: {}", path);
                    return Ok(PathBuf::from(path));
                }
            }
        }

        warn!("未能解析进程路径，PID: {}", pid);
        Err(WeChatError::ProcessNotFound.into())
    }

    /// 从可执行文件路径检测版本
    async fn detect_version_from_path(&self, exe_path: &PathBuf) -> Result<WeChatVersion> {
        // 首先尝试使用PowerShell获取文件版本信息
        if let Ok(version_str) = self.get_file_version_powershell(exe_path).await {
            debug!("检测到版本信息: {}", version_str);

            if version_str.starts_with("4.") {
                return Ok(WeChatVersion::V4x { exact: version_str });
            } else if version_str.starts_with("3.") {
                return Ok(WeChatVersion::V3x { exact: version_str });
            }
        }

        tracing::info!("无法从版本信息判断，尝试从路径和文件名判断");
        // 如果无法从版本信息判断，尝试从路径和文件名判断
        let path_str = exe_path.to_string_lossy().to_lowercase();
        let file_name = exe_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        if file_name == "wechat.exe" {
            // 对于WeChat.exe，尝试从PowerShell获取的版本信息中提取
            // 如果没有获取到具体版本，返回Unknown让其他方式处理
            Ok(WeChatVersion::Unknown)
        } else {
            // 其他文件名都返回Unknown
            Ok(WeChatVersion::Unknown)
        }
    }

    /// 使用PowerShell获取文件版本信息
    async fn get_file_version_powershell(&self, exe_path: &PathBuf) -> Result<String> {
        let path_str = exe_path.to_string_lossy();
        let script = format!(
            "(Get-ItemProperty '{}').VersionInfo.FileVersion",
            path_str.replace("'", "''")
        );

        let output = Command::new("powershell")
            .args(&["-Command", &script])
            .output()
            .map_err(|_| WeChatError::ProcessNotFound)?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            debug!("PowerShell返回版本: '{}'", version);

            // 验证版本号格式：必须包含数字和点，且不能是占位符
            if !version.is_empty()
                && version != "null"
                && version.chars().any(|c| c.is_ascii_digit())
                && version.contains('.')
                && !version.contains('x')
                && !version.to_lowercase().contains("unknown")
            {
                debug!("有效版本号: {}", version);
                return Ok(version);
            } else {
                debug!("无效版本号格式: {}", version);
            }
        } else {
            let error_output = String::from_utf8_lossy(&output.stderr);
            debug!("PowerShell执行失败: {}", error_output);
        }

        Err(WeChatError::ProcessNotFound.into())
    }

    /// 定位微信数据目录
    async fn find_data_directory(&self, process: &ProcessInfo) -> Result<Option<PathBuf>> {
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
    pub async fn get_main_wechat_processes(&self) -> Result<Vec<ProcessInfo>> {
        let all_processes = self.detect_processes().await?;
        println!("检测到 {} 个微信相关进程", all_processes.len());

        Ok(all_processes
            .into_iter()
            // .filter(|process| process.name.eq_ignore_ascii_case("WeChat.exe") | process.name.eq_ignore_ascii_case("Weixin.exe"))
            .collect())
    }

    /// 验证进程版本是否有效（包含数字和点号，非Unknown）
    pub fn validate_process_version(&self, process: &ProcessInfo) -> bool {
        match &process.version {
            WeChatVersion::V3x { exact } | WeChatVersion::V4x { exact } => {
                exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.')
            }
            WeChatVersion::V3xW { exact } | WeChatVersion::V4xW { exact } => {
                exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.')
            }
            WeChatVersion::Unknown => false,
        }
    }

    /// 获取有效版本的 WeChat.exe 主进程
    pub async fn get_valid_main_processes(&self) -> Result<Vec<ProcessInfo>> {
        tracing::info!("开始获取有效的WeChat.exe主进程...");
        let main_processes = self.get_main_wechat_processes().await?;
        Ok(main_processes
            .into_iter()
            .filter(|p| self.validate_process_version(p))
            .collect())
    }

    /// 获取所有微信进程（包括子进程）- 保持向后兼容
    pub async fn get_all_wechat_processes(&self) -> Result<Vec<ProcessInfo>> {
        self.detect_processes().await
    }
}

#[async_trait]
impl ProcessDetector for WindowsProcessDetector {
    async fn detect_processes(&self) -> Result<Vec<ProcessInfo>> {
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

            let mut process_info = ProcessInfo {
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

    async fn get_process_info(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        let processes = self.detect_processes().await?;
        Ok(processes.into_iter().find(|p| p.pid == pid))
    }

    async fn detect_version(&self, exe_path: &PathBuf) -> Result<WeChatVersion> {
        self.detect_version_from_path(exe_path).await
    }

    async fn locate_data_dir(&self, process: &ProcessInfo) -> Result<Option<PathBuf>> {
        self.find_data_directory(process).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detector_creation() {
        let detector = WindowsProcessDetector::new();
        assert!(detector.is_ok());
    }

    #[tokio::test]
    async fn test_process_detection() {
        let detector = WindowsProcessDetector::new().unwrap();
        let result = detector.detect_processes().await;

        // 测试不应该失败，即使没有找到微信进程
        assert!(result.is_ok());

        let processes = result.unwrap();
        println!("检测到的微信进程数量: {}", processes.len());

        for process in processes {
            println!(
                "进程: {} (PID: {}, 版本: {:?})",
                process.name, process.pid, process.version
            );
        }
        #[tokio::test]
        async fn test_get_main_wechat_processes() {
            let detector = WindowsProcessDetector::new().unwrap();
            let result = detector.get_main_wechat_processes().await;

            // 测试应该成功，即使没有找到WeChat.exe进程
            assert!(result.is_ok());

            let main_processes = result.unwrap();
            println!("检测到的WeChat.exe主进程数量: {}", main_processes.len());

            // 验证所有返回的进程都是WeChat.exe
            for process in &main_processes {
                assert!(process.name.eq_ignore_ascii_case("WeChat.exe"));
                println!(
                    "主进程: {} (PID: {}, 版本: {:?})",
                    process.name, process.pid, process.version
                );
            }
        }

        #[tokio::test]
        async fn test_validate_process_version() {
            let detector = WindowsProcessDetector::new().unwrap();

            // 创建测试用的进程信息
            let valid_v3_process = ProcessInfo {
                pid: 1234,
                name: "WeChat.exe".to_string(),
                path: std::path::PathBuf::from("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe"),
                version: WeChatVersion::V3x {
                    exact: "3.9.5.81".to_string(),
                },
                data_dir: None,
                detected_at: chrono::Utc::now(),
            };

            let valid_v4_process = ProcessInfo {
                pid: 5678,
                name: "WeChat.exe".to_string(),
                path: std::path::PathBuf::from("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe"),
                version: WeChatVersion::V4x {
                    exact: "4.0.0.1000".to_string(),
                },
                data_dir: None,
                detected_at: chrono::Utc::now(),
            };

            let invalid_unknown_process = ProcessInfo {
                pid: 9999,
                name: "WeChat.exe".to_string(),
                path: std::path::PathBuf::from("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe"),
                version: WeChatVersion::Unknown,
                data_dir: None,
                detected_at: chrono::Utc::now(),
            };

            let invalid_v3_process = ProcessInfo {
                pid: 1111,
                name: "WeChat.exe".to_string(),
                path: std::path::PathBuf::from("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe"),
                version: WeChatVersion::V3x {
                    exact: "unknown".to_string(),
                },
                data_dir: None,
                detected_at: chrono::Utc::now(),
            };

            // 测试有效版本
            assert!(detector.validate_process_version(&valid_v3_process));
            assert!(detector.validate_process_version(&valid_v4_process));

            // 测试无效版本
            assert!(!detector.validate_process_version(&invalid_unknown_process));
            assert!(!detector.validate_process_version(&invalid_v3_process));

            println!("版本验证测试通过");
        }

        #[tokio::test]
        async fn test_get_valid_main_processes() {
            let detector = WindowsProcessDetector::new().unwrap();
            let result = detector.get_valid_main_processes().await;

            // 测试应该成功
            assert!(result.is_ok());
            let valid_processes = result.unwrap();
            println!(
                "检测到的有效WeChat.exe主进程数量: {}",
                valid_processes.len()
            );

            // 验证所有返回的进程都是WeChat.exe且版本有效
            for process in &valid_processes {
                assert!(process.name.eq_ignore_ascii_case("WeChat.exe"));
                assert!(detector.validate_process_version(process));
                println!(
                    "有效主进程: {} (PID: {}, 版本: {:?})",
                    process.name, process.pid, process.version
                );
            }
        }

        #[tokio::test]
        async fn test_get_all_wechat_processes() {
            let detector = WindowsProcessDetector::new().unwrap();
            let result = detector.get_all_wechat_processes().await;

            // 测试应该成功
            assert!(result.is_ok());

            let all_processes = result.unwrap();
            println!("检测到的所有微信进程数量: {}", all_processes.len());

            // 验证所有返回的进程都是微信相关进程
            for process in &all_processes {
                let is_wechat_process = detector
                    .wechat_process_names
                    .iter()
                    .any(|name| process.name.eq_ignore_ascii_case(name));
                assert!(
                    is_wechat_process,
                    "进程 {} 不在微信进程名列表中",
                    process.name
                );
            }
        }
    }
}
