
use crate::errors::WeChatError;
use crate::errors::SystemError;
use crate::errors::Result;
use crate::utils::ProcessInfo;
use crate::wechat::WeChatVersion;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;


#[cfg(target_os = "windows")]
use super::windows as platform_impl;

#[cfg(target_os = "macos")]
use self::macos as platform_impl;

/// 进程信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WechatProcessInfo {
    /// 进程ID
    pub pid: u32,
    /// 进程名称
    pub name: String,
    /// 是否为主进程
    pub is_main_process: bool,
    /// 可执行文件路径
    pub path: PathBuf,
    /// 微信版本
    pub version: WeChatVersion,
    /// 数据目录
    pub data_dir: Option<PathBuf>,
    /// 检测时间
    pub detected_at: DateTime<Utc>,
}

impl WechatProcessInfo {
    /// 检查进程是否仍在运行
    pub async fn is_running(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            return crate::utils::windows::process::is_process_running(self.pid);
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

    // pub fn set_version();
    pub fn is_wxwork(&self) -> bool {
        platform_impl::is_wxwork(self)
    }

    /// 从一个更通用的 ProcessInfo 实例创建 WechatProcessInfo。
    ///
    /// 这个转换是可失败的，如果缺少必要信息（如路径或可解析的版本），
    /// 将会返回一个错误。
    pub fn new(process_info: ProcessInfo) -> Result<Self> {
        // 1. 处理路径：目标结构体中这是必需的。
        // 我们使用 `ok_or` 将 Option 转换为 Result。
        let path_str = process_info.path.ok_or(SystemError::MissingPath)?;
        let path = PathBuf::from(path_str);

        // 2. 处理版本：解析可选的版本字符串。
        // 如果版本字符串是 None，我们可以默认为 Unknown。
        // 如果是 Some，我们就尝试解析它。
        // let version = match process_info.version {
        //     Some(v_str) => v_str.parse::<WeChatVersion>()?, // '?' 会自动传递 ConversionError
        //     None => WeChatVersion::Unknown,                 // 或者如果未知版本不允许，就返回错误
        // };

        let version = match process_info.version {
            Some(v_str) => {
                // 首先，尝试解析版本字符串
                let parsed_version = v_str.parse::<WeChatVersion>()?;

                // 接着，检查解析后的版本是否是 V3x
                match parsed_version {
                    // 如果是 V3x，则返回不支持的版本错误
                    WeChatVersion::V3x { exact } => {
                        return Err(WeChatError::UnsupportedVersion { version: exact }.into());
                    }
                    // 如果是 V4x 或其他可接受的版本，则继续
                    v @ WeChatVersion::V4x { .. } => v,
                    // Unknown 理论上不会从 parse 产生，但为了代码健壮性，我们处理它
                    WeChatVersion::Unknown => WeChatVersion::Unknown,
                }
            }
            // 如果版本字符串不存在，则默认为 Unknown
            None => WeChatVersion::Unknown,
        };

        // 3. 组装新的结构体
        Ok(Self {
            // 尽可能地从 process_info 直接移动（move）值，以提高效率
            pid: process_info.pid,
            name: process_info.name, // name 是 String，可以直接移动
            is_main_process:process_info.is_main_process,
            path,
            version,
            // 初始化源结构体中不存在的字段
            data_dir: None,          // 我们没有这个信息，所以初始化为 None
            detected_at: Utc::now(), // 将检测时间设置为当前时间
        })
    }
}
