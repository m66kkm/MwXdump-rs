pub mod process_detector;
pub mod wechat_process_info;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "macos")]
mod macos;

pub use process_detector::ProcessDetector;
pub use wechat_process_info::WechatProcessInfo;
pub use process_detector::create_detector;