//! 辅助类
//!

pub mod windows;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub parent_pid: u32, // 父进程的 PID
    pub pid: u32,
    pub name: String,
    pub path: Option<String>, // 可选的进程路径
    pub version: Option<String>, // 可选的版本信息
    pub is_64_bit: bool, // 是否为 64 位进程
    pub is_main_process: bool, // 是否为主进程

}

impl ProcessInfo {
    pub fn new(parent_pid: u32,  pid: u32, name: String, path: Option<String>, version: Option<String>, is_64_bit: bool, is_main_process: bool) -> Self {
        Self {
            parent_pid,
            pid,
            name,
            path,
            version,
            is_64_bit,
            is_main_process
        }
    }

    pub fn display(&self) -> String {
        let mut info = format!("PID: {}, Name: {}", self.pid, self.name);
        if let Some(ref path) = self.path {
            info.push_str(&format!(", Path: {}", path));
        }
        if let Some(ref version) = self.version {
            info.push_str(&format!(", Version: {}", version));
        }
        info.push_str(&format!(", 64-bit: {}", self.is_64_bit));
        info
    }
}
