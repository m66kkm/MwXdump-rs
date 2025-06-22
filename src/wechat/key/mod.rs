//! 微信密钥提取模块
//!
//! 该模块负责从微信进程内存中提取数据库解密密钥

pub mod key_extractor;
pub mod key_version;
pub mod wechatkey;

#[cfg(target_os = "windows")]
mod windows;
// #[cfg(target_os = "macos")]
// mod macos;

pub use key_extractor::KeyExtractor;
pub use key_version::KeyVersion;
pub use wechatkey::WeChatKey;
pub use wechatkey::KeyValidator;