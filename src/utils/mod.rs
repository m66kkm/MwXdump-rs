//! 辅助类
//!


pub mod  win_process_detector;
pub mod win_registry;
pub mod win_memory;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>, // 可选的进程路径
    pub version: Option<String>, // 可选的版本信息
    pub is_64_bit: bool, // 是否为 64 位进程
}
