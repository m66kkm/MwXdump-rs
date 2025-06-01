//! Windows API 绑定模块
//!
//! 提供密钥提取所需的Windows API函数封装

use std::ffi::c_void;
use std::mem;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle};
use windows_result::BOOL;

use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use crate::errors::{Result, WeChatError};
use tracing::{debug, warn};

/// 内存基本信息
#[derive(Debug, Clone)]
pub struct MemoryInfo {
    pub base_address: usize,
    pub region_size: usize,
    pub protect: u32,
    pub state: u32,
}

/// 模块信息
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: usize,
    pub size: usize,
}

/// Windows API 封装器
pub struct WindowsApi {
    pub process_handle: HANDLE,
}

impl WindowsApi {
    /// 打开进程
    pub fn open_process(pid: u32) -> Result<Self> {
        debug!("正在打开进程 PID: {}", pid);
        
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        };
        
        match handle {
            Ok(h) if h != INVALID_HANDLE_VALUE  => {
                debug!("成功打开进程，句柄: {:?}", h);
                Ok(Self {
                    process_handle: h,
                })
            }
            _ => {
                let error = std::io::Error::last_os_error();
                warn!("打开进程失败 PID: {}, 错误: {}", pid, error);
                Err(WeChatError::ProcessNotFound.into())
            }
        }
    }
    
    /// 查找指定模块
    pub fn find_module(&self, pid: u32, module_name: &str) -> Result<Option<ModuleInfo>> {
        debug!("正在查找模块: {} (PID: {})", module_name, pid);
        
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        };
        
        let snapshot = match snapshot {
            Ok(h) if h != INVALID_HANDLE_VALUE => h,
            _ => {
                let error = std::io::Error::last_os_error();
                warn!("创建模块快照失败 PID: {}, 错误: {}", pid, error);
                return Err(WeChatError::ProcessNotFound.into());
            }
        };
        
        let mut module_entry = MODULEENTRY32W {
            dwSize: mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        
        // 获取第一个模块
        let first_result = unsafe { Module32FirstW(snapshot, &mut module_entry) };
        if first_result.is_err() {
            unsafe { CloseHandle(snapshot) };
            return Ok(None);
        }
        
        loop {
            // 转换模块名称
            let current_name = unsafe {
                let name_slice = std::slice::from_raw_parts(
                    module_entry.szModule.as_ptr(),
                    module_entry.szModule.len(),
                );
                String::from_utf16_lossy(name_slice).trim_end_matches('\0').to_string()
            };
            
            debug!("找到模块: {}", current_name);
            
            if current_name.eq_ignore_ascii_case(module_name) {
                let module_info = ModuleInfo {
                    name: current_name,
                    base_address: module_entry.modBaseAddr as usize,
                    size: module_entry.modBaseSize as usize,
                };
                
                debug!("找到目标模块: {:?}", module_info);
                unsafe { CloseHandle(snapshot) };
                return Ok(Some(module_info));
            }
            
            // 获取下一个模块
            let next_result = unsafe { Module32NextW(snapshot, &mut module_entry) };
            if next_result.is_err() {
                break;
            }
        }
        
        unsafe { windows::Win32::Foundation::CloseHandle(snapshot) };
        debug!("未找到模块: {}", module_name);
        Ok(None)
    }
    
    /// 查询内存区域信息
    pub fn query_memory(&self, address: usize) -> Result<Option<MemoryInfo>> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        
        let result = unsafe {
            VirtualQueryEx(
                self.process_handle,
                Some(address as *const c_void),
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        
        if result == 0 {
            return Ok(None);
        }
        
        Ok(Some(MemoryInfo {
            base_address: mbi.BaseAddress as usize,
            region_size: mbi.RegionSize,
            protect: mbi.Protect.0,
            state: mbi.State.0,
        }))
    }
    
    /// 检查内存区域是否可写
    pub fn is_writable_memory(&self, memory_info: &MemoryInfo) -> bool {
        let writable_flags = PAGE_READWRITE.0 
            | PAGE_WRITECOPY.0 
            | PAGE_EXECUTE_READWRITE.0 
            | PAGE_EXECUTE_WRITECOPY.0;
        
        (memory_info.protect & writable_flags) > 0 && memory_info.state == MEM_COMMIT.0
    }
    
    /// 读取进程内存
    pub fn read_memory(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;
        
        let result = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut bytes_read),
            )
        };
        
        match result {
            Ok(_) if bytes_read == size => {
                debug!("成功读取内存: 地址=0x{:X}, 大小={} 字节", address, size);
                Ok(buffer)
            }
            _ => {
                let error = std::io::Error::last_os_error();
                warn!("读取内存失败: 地址=0x{:X}, 大小={}, 错误: {}", address, size, error);
                Err(WeChatError::KeyExtractionFailed(format!("内存读取失败: {}", error)).into())
            }
        }
    }
    
    /// 枚举模块内的可写内存区域
    pub fn enumerate_writable_regions(&self, module: &ModuleInfo) -> Result<Vec<MemoryInfo>> {
        debug!("枚举模块 {} 的可写内存区域", module.name);
        
        let mut regions = Vec::new();
        let mut current_address = module.base_address;
        let end_address = module.base_address + module.size;
        
        while current_address < end_address {
            if let Some(memory_info) = self.query_memory(current_address)? {
                // 检查区域大小，跳过小于100KB的区域
                if memory_info.region_size >= 100 * 1024 && self.is_writable_memory(&memory_info) {
                    debug!("找到可写内存区域: 0x{:X} - 0x{:X}, 大小: {} KB", 
                           memory_info.base_address, 
                           memory_info.base_address + memory_info.region_size,
                           memory_info.region_size / 1024);
                    regions.push(memory_info.clone());
                }
                
                current_address = memory_info.base_address + memory_info.region_size;
            } else {
                // 如果查询失败，移动到下一个页面
                current_address += 4096; // 标准页面大小
            }
        }
        
        debug!("找到 {} 个可写内存区域", regions.len());
        Ok(regions)
    }
}

impl Drop for WindowsApi {
    fn drop(&mut self) {
        if self.process_handle != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.process_handle);
            }
            debug!("已关闭进程句柄");
        }
    }
}

// SAFETY: WindowsApi 是线程安全的，因为：
// 1. Windows HANDLE 是内核对象的不透明引用，可以安全地在线程间共享
// 2. 所有使用 HANDLE 的 Windows API 函数都是线程安全的
// 3. WindowsApi 的所有方法都使用不可变引用 (&self)
unsafe impl Send for WindowsApi {}
unsafe impl Sync for WindowsApi {}

/// 检查进程是否为64位
pub fn is_64bit_process(handle: HANDLE) -> Result<bool> {
    use windows::Win32::System::Threading::IsWow64Process;
    
    let mut is_wow64 = BOOL::from(false);
    let result = unsafe { IsWow64Process(handle, &mut is_wow64) };
    
    match result {
        Ok(_) => {
            // 如果是WOW64进程，说明是32位进程运行在64位系统上
            // 如果不是WOW64进程，需要进一步判断
            if is_wow64.as_bool() {
                Ok(false) // 32位进程
            } else {
                // 在64位系统上，非WOW64进程就是64位进程
                // 在32位系统上，所有进程都是32位的
                #[cfg(target_pointer_width = "64")]
                {
                    Ok(true) // 64位进程
                }
                #[cfg(target_pointer_width = "32")]
                {
                    Ok(false) // 32位进程
                }
            }
        }
        Err(e) => {
            warn!("检查进程架构失败: {}", e);
            Err(WeChatError::ProcessNotFound.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_info_creation() {
        let info = MemoryInfo {
            base_address: 0x1000,
            region_size: 4096,
            protect: PAGE_READWRITE.0,
            state: MEM_COMMIT.0,
        };
        
        assert_eq!(info.base_address, 0x1000);
        assert_eq!(info.region_size, 4096);
    }
    
    #[test]
    fn test_module_info_creation() {
        let info = ModuleInfo {
            name: "test.dll".to_string(),
            base_address: 0x10000000,
            size: 1024 * 1024,
        };
        
        assert_eq!(info.name, "test.dll");
        assert_eq!(info.base_address, 0x10000000);
        assert_eq!(info.size, 1024 * 1024);
    }
}