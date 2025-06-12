use super::super::WeChatVersion;
use super::{ProcessDetector, WechatProcessInfo};

use once_cell::sync::Lazy;
use windows::Win32::System::Registry::HKEY_CURRENT_USER;

const WECHAT_REG_KEY_PATH: &str = "Software\\Tencent\\WeChat";
const WECHAT_FILES_VALUE_NAME: &str = "FileSavePath";
static WECHAT_PROCESS_NAMES: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "WeChat.exe",
        "Weixin.exe", // 微信4.0的主可执行文件名
        "WeChatApp.exe",
        "Weixin.dll"
        // "WeChatAppEx.exe", // 微信增强版
    ]
});

const WXWork_REG_KEY_PATH: &str = "Software\\Tencent\\WeChat";
const WXWork_FILES_VALUE_NAME: &str = "FileSavePath";
static WXWORK_PROCESS_NAMES: Lazy<Vec<&'static str>> = Lazy::new(|| vec!["WXWork.exe"]);

pub fn is_wxwork(process: &WechatProcessInfo) -> bool {
    if WXWORK_PROCESS_NAMES
        .iter()
        .any(|wxwork_name| process.name.eq_ignore_ascii_case(wxwork_name))
    {
        return true;
    }
    return false;
}

pub struct WindowsProcessDetector {
    /// 微信进程名称列表
    wechat_process_names: Vec<String>,
}

pub mod windows_process_detector;
