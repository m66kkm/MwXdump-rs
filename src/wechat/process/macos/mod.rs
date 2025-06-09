//! macOS平台的微信进程检测实现

use super::{ProcessDetector, ProcessInfo, WeChatVersion};
use crate::errors::{Result, WeChatError};
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, error, info, warn};

/// macOS平台的进程检测器
pub struct MacOSProcessDetector {
    /// 微信进程名称列表
    wechat_process_names: Vec<String>,
}

impl MacOSProcessDetector {
    /// 创建新的macOS进程检测器
    pub fn new() -> Result<Self> {
        Ok(Self {
            wechat_process_names: vec![
                "WeChat".to_string(),
                "微信".to_string(),
            ],
        })
    }

    /// 使用ps命令获取进程列表
    async fn get_process_list(&self) -> Result<Vec<(u32, String, String)>> {
        let output = Command::new("ps")
            .args(&["-axo", "pid,comm,args"])
            .output()
            .map_err(|e| WeChatError::ProcessNotFound)?;

        if !output.status.success() {
            return Err(WeChatError::ProcessNotFound.into());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();

        for line in output_str.lines().skip(1) {
            let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
            if parts.len() >= 3 {
                if let Ok(pid) = parts[0].parse::<u32>() {
                    let comm = parts[1].to_string();
                    let args = parts[2].to_string();
                    processes.push((pid, comm, args));
                }
            }
        }

        Ok(processes)
    }

    /// 从应用路径检测版本
    async fn detect_version_from_path(&self, app_path: &PathBuf) -> Result<WeChatVersion> {
        // 尝试读取Info.plist文件
        let info_plist_path = app_path.join("Contents").join("Info.plist");
        
        if info_plist_path.exists() {
            // 使用plutil命令读取版本信息
            if let Ok(output) = Command::new("plutil")
                .args(&["-p", info_plist_path.to_str().unwrap()])
                .output()
            {
                let plist_content = String::from_utf8_lossy(&output.stdout);
                
                // 查找CFBundleShortVersionString
                for line in plist_content.lines() {
                    if line.contains("CFBundleShortVersionString") {
                        if let Some(version_start) = line.find('"') {
                            if let Some(version_end) = line.rfind('"') {
                                if version_start < version_end {
                                    let version = line[version_start + 1..version_end].to_string();
                                    debug!("检测到版本信息: {}", version);
                                    
                                    if version.starts_with("4.") {
                                        return Ok(WeChatVersion::V40 { exact: version });
                                    } else if version.starts_with("3.") {
                                        return Ok(WeChatVersion::V3x { exact: version });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 如果无法从Info.plist获取版本，尝试从路径判断
        let path_str = app_path.to_string_lossy().to_lowercase();
        if path_str.contains("4.0") {
            Ok(WeChatVersion::V40 { exact: "4.0.x".to_string() })
        } else {
            Ok(WeChatVersion::V3x { exact: "3.x.x".to_string() })
        }
    }

    /// 定位微信数据目录
    async fn find_data_directory(&self, process: &ProcessInfo) -> Result<Option<PathBuf>> {
        // macOS微信数据目录的常见位置
        let home_dir = dirs::home_dir().ok_or_else(|| WeChatError::ProcessNotFound)?;
        
        let possible_dirs = vec![
            // ~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat
            home_dir.join("Library")
                .join("Containers")
                .join("com.tencent.xinWeChat")
                .join("Data")
                .join("Library")
                .join("Application Support")
                .join("com.tencent.xinWeChat"),
            // ~/Documents/WeChat Files
            home_dir.join("Documents").join("WeChat Files"),
            // ~/Library/Application Support/WeChat
            home_dir.join("Library")
                .join("Application Support")
                .join("WeChat"),
        ];

        for dir in possible_dirs {
            if dir.exists() && dir.is_dir() {
                info!("找到微信数据目录: {:?}", dir);
                return Ok(Some(dir));
            }
        }

        warn!("未找到微信数据目录");
        Ok(None)
    }

    /// 获取应用程序的完整路径
    async fn get_app_path(&self, pid: u32) -> Result<PathBuf> {
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "args="])
            .output()
            .map_err(|e| WeChatError::ProcessNotFound)?;

        if !output.status.success() {
            return Err(WeChatError::ProcessNotFound.into());
        }

        let args = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        // 提取.app路径
        if let Some(app_start) = args.find(".app") {
            let mut app_end = app_start + 4;
            let mut path_start = 0;
            
            // 向前查找路径开始
            for (i, c) in args.char_indices().rev() {
                if i >= app_start {
                    continue;
                }
                if c == ' ' && !args[i+1..].starts_with('/') {
                    path_start = i + 1;
                    break;
                }
            }
            
            let app_path = &args[path_start..app_end];
            return Ok(PathBuf::from(app_path));
        }

        Err(WeChatError::ProcessNotFound.into())
    }
}

#[async_trait]
impl ProcessDetector for MacOSProcessDetector {
    async fn detect_processes(&self) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        let process_list = self.get_process_list().await?;

        for (pid, comm, args) in process_list {
            // 检查是否为微信进程
            let is_wechat = self.wechat_process_names.iter().any(|name| {
                comm.contains(name) || args.contains(name)
            });

            if is_wechat {
                debug!("发现微信进程: {} (PID: {})", comm, pid);

                match self.get_app_path(pid).await {
                    Ok(path) => {
                        // 检测版本
                        let version = self.detect_version_from_path(&path).await
                            .unwrap_or(WeChatVersion::Unknown);

                        let mut process_info = ProcessInfo {
                            pid,
                            name: comm,
                            path,
                            version,
                            data_dir: None,
                            detected_at: Utc::now(),
                        };

                        // 尝试定位数据目录
                        process_info.data_dir = self.find_data_directory(&process_info).await.ok().flatten();

                        processes.push(process_info);
                    }
                    Err(e) => {
                        warn!("无法获取进程路径 PID {}: {}", pid, e);
                    }
                }
            }
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
        let detector = MacOSProcessDetector::new();
        assert!(detector.is_ok());
    }

    #[tokio::test]
    async fn test_process_detection() {
        let detector = MacOSProcessDetector::new().unwrap();
        let result = detector.detect_processes().await;
        
        // 测试不应该失败，即使没有找到微信进程
        assert!(result.is_ok());
        
        let processes = result.unwrap();
        println!("检测到的微信进程数量: {}", processes.len());
        
        for process in processes {
            println!("进程: {} (PID: {}, 版本: {:?})", 
                process.name, process.pid, process.version);
        }
    }
}