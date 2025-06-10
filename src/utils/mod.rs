//! 辅助类
//!

pub mod win_registry;
pub mod win_memory;
pub mod win_process;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>, // 可选的进程路径
    pub version: Option<String>, // 可选的版本信息
    pub is_64_bit: bool, // 是否为 64 位进程
}

impl ProcessInfo {
    pub fn new(pid: u32, name: String, path: Option<String>, version: Option<String>, is_64_bit: bool) -> Self {
        Self {
            pid,
            name,
            path,
            version,
            is_64_bit,
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
