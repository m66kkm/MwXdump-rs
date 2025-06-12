use std::{
    ffi::c_void,
    ops::{Deref, DerefMut},
};

use anyhow::bail;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
                },
            },
            Memory::{
                VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
            },
            Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
};

#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
}

pub type Result<T> = crate::Result<T>;

// --- RAII 包装器，用于自动关闭 Windows 句柄 ---
#[derive(Debug)]
struct Handle(HANDLE);

impl Handle {
    fn new(handle: HANDLE) -> Result<Self> {
        if handle == INVALID_HANDLE_VALUE || handle.is_invalid() {
            Err(windows::core::Error::from_win32().into())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

impl Deref for Handle {
    type Target = HANDLE;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for Handle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
// --- RAII 包装器结束 ---


/// 从指定进程读取一块内存。
pub fn read_process_memory(pid: u32, address: usize, size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    // FIX: 先用 ? 解包 OpenProcess 返回的 Result<HANDLE, Error>
    let process_handle = Handle::new(unsafe { OpenProcess(PROCESS_VM_READ, false, pid)? })?;

    let mut buffer: Vec<u8> = vec![0; size];
    let mut bytes_read: usize = 0;

    unsafe {
        ReadProcessMemory(
            *process_handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            Some(&mut bytes_read),
        )?;
    };

    buffer.truncate(bytes_read);
    Ok(buffer)
}

/// 获取进程中指定模块的基址。
pub fn get_module_base_address(pid: u32, module_name: &str) -> Result<usize> {
    // FIX: 先用 ? 解包 CreateToolhelp32Snapshot 返回的 Result<HANDLE, Error>
    let snapshot_handle = Handle::new(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?
    })?;

    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    unsafe { Module32FirstW(*snapshot_handle, &mut module_entry)? };

    loop {
        let current_module_name =
            unsafe { PCWSTR::from_raw(module_entry.szModule.as_ptr()).to_string()? };

        if current_module_name.eq_ignore_ascii_case(module_name) {
            return Ok(module_entry.modBaseAddr as usize);
        }

        if unsafe { Module32NextW(*snapshot_handle, &mut module_entry) }.is_err() {
            break;
        }
    }

    Err(anyhow::anyhow!("Module '{}' not found in PID {}", module_name, pid))
}

const SCAN_BUFFER_SIZE: usize = 4096 * 2;

/// 在进程的指定内存区域内搜索字节模式。
pub fn search_memory_for_pattern(
    pid: u32,
    pattern: &[u8],
    start_address: usize,
    end_address: usize,
    max_occurrences: usize,
) -> Result<Vec<usize>> {
    tracing::info!(
        "Searching for pattern {:02X?} in process {} from {:#x} to {:#x}",
        pattern,
        pid,
        start_address,
        end_address
    );

    if pattern.is_empty() {
        return Ok(Vec::new());
    }

    // FIX: 先用 ? 解包 OpenProcess 返回的 Result<HANDLE, Error>
    let process_handle = Handle::new(unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)?
    })?;

    let mut found_addresses = Vec::new();
    let mut current_address = start_address;

    let mut buffer = vec![0u8; SCAN_BUFFER_SIZE + pattern.len() - 1];
    let mut previous_read_size = 0;

    while current_address < end_address && found_addresses.len() < max_occurrences {
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        if unsafe {
            VirtualQueryEx(
                *process_handle,
                Some(current_address as *const c_void),
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0 {
            break;
        }

        let region_base = mem_info.BaseAddress as usize;
        let region_end = region_base.saturating_add(mem_info.RegionSize);
        
        let is_readable_and_committed = mem_info.State == MEM_COMMIT &&
            (mem_info.Protect == PAGE_READWRITE
                || mem_info.Protect == PAGE_READONLY
                || mem_info.Protect == PAGE_EXECUTE_READ
                || mem_info.Protect == PAGE_EXECUTE_READWRITE);

        if is_readable_and_committed {
            let mut scan_ptr = current_address.max(region_base);
            while scan_ptr < region_end && found_addresses.len() < max_occurrences {
                let overlap_size = if previous_read_size > 0 { pattern.len() - 1 } else { 0 };
                if overlap_size > 0 {
                    let start = previous_read_size - overlap_size;
                    buffer.copy_within(start..previous_read_size, 0);
                }

                let bytes_to_read = (SCAN_BUFFER_SIZE).min(region_end - scan_ptr);
                let mut bytes_read = 0;
                
                let read_ok = unsafe {
                    ReadProcessMemory(
                        *process_handle,
                        scan_ptr as *const c_void,
                        buffer.as_mut_ptr().add(overlap_size) as *mut c_void,
                        bytes_to_read,
                        Some(&mut bytes_read),
                    )
                }.is_ok();

                if read_ok && bytes_read > 0 {
                    let search_area = &buffer[..overlap_size + bytes_read];
                    for (i, window) in search_area.windows(pattern.len()).enumerate() {
                        if window == pattern {
                            let match_addr = (scan_ptr - overlap_size) + i;
                            
                            if !found_addresses.ends_with(&[match_addr]) {
                                found_addresses.push(match_addr);
                                if found_addresses.len() >= max_occurrences {
                                    return Ok(found_addresses);
                                }
                            }
                        }
                    }
                }
                
                previous_read_size = overlap_size + bytes_read;
                scan_ptr += bytes_read;

                if bytes_read == 0 {
                    break;
                }
            }
        }
        
        current_address = region_end;
        if current_address < region_base {
            break;
        }
    }

    Ok(found_addresses)
}


/// 获取进程中指定模块的信息（基址和大小）。
pub fn get_module_info(pid: u32, module_name: &str) -> Result<ModuleInfo> {
    // 使用 RAII 包装器
    let snapshot_handle = Handle::new(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?
    })?;

    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    // 遍历模块
    if unsafe { Module32FirstW(*snapshot_handle, &mut module_entry) }.is_ok() {
        loop {
            let current_module_name =
                unsafe { PCWSTR::from_raw(module_entry.szModule.as_ptr()).to_string()? };

            if current_module_name.eq_ignore_ascii_case(module_name) {
                // 找到匹配的模块，返回包含基址和大小的结构体
                return Ok(ModuleInfo {
                    base_address: module_entry.modBaseAddr as usize,
                    size: module_entry.modBaseSize as usize,
                });
            }

            if unsafe { Module32NextW(*snapshot_handle, &mut module_entry) }.is_err() {
                break; // 遍历结束
            }
        }
    } else {
        // 如果 Module32FirstW 失败，返回Win32错误
        return Err(windows::core::Error::from_win32().into());
    }
    
    // 如果循环结束仍未找到，返回自定义错误
    // bail!(Error!("Module '{}' not found in PID {}", module_name, pid))
    bail!(crate::errors::SystemError::ModuleInfoMissing {
        value: module_name.to_string(),
        pid
    })
}


/// 读取指定进程中特定模块的完整内存内容。
///
/// # Arguments
/// * `pid` - 目标进程的 ID.
/// * `module_name` - 目标模块的名称 (例如 "Weixin.exe" 或 "ntdll.dll").
///
/// # Returns
/// 返回一个包含模块所有字节的 Vec<u8>。
pub fn read_module_memory(pid: u32, module_name: &str) -> Result<Vec<u8>> {
    // 1. 获取模块的基址和大小
    let module_info = get_module_info(pid, module_name)?;
    
    println!(
        "Found module '{}' at base address {:#x} with size {} bytes.",
        module_name, module_info.base_address, module_info.size
    );

    // 2. 使用获取到的信息读取整个模块的内存
    let module_content = read_process_memory(pid, module_info.base_address, module_info.size)?;

    Ok(module_content)
}

/// 在指定进程的特定模块内搜索字节模式。
///
/// 这是一个高效的实现，它将整个模块读入内存，然后在本地进行搜索。
///
/// # Arguments
/// * `pid` - 目标进程的 ID.
/// * `module_name` - 要搜索的模块名称 (例如 "ntdll.dll").
/// * `pattern` - 要搜索的字节序列 (AOB pattern).
/// * `max_occurrences` - 找到多少个匹配项后停止搜索。
///
/// # Returns
/// 返回一个包含所有匹配地址的 Vec<usize>。
pub fn search_module_for_pattern(
    pid: u32,
    module_name: &str,
    pattern: &[u8],
    max_occurrences: usize,
) -> Result<Vec<usize>> {
    tracing::info!(
        "Searching for pattern {:02X?} in module '{}' of process {}",
        pattern,
        module_name,
        pid
    );

    if pattern.is_empty() {
        return Ok(Vec::new());
    }

    // 1. 获取模块信息，这是我们搜索的边界
    let module_info = get_module_info(pid, module_name)?;
    
    // 2. 将整个模块的内容一次性读入本地内存
    // 我们复用之前编写的 read_module_memory 函数
    let module_bytes = read_process_memory(pid, module_info.base_address, module_info.size)?;

    if module_bytes.len() != module_info.size {
        tracing::warn!(
            "Read {} bytes from module '{}', but its expected size was {}. The search will proceed with the read data.",
            module_bytes.len(),
            module_name,
            module_info.size
        );
    }

    // 3. 在本地字节缓冲区中进行高效搜索
    let mut found_addresses = Vec::new();
    for (index, window) in module_bytes.windows(pattern.len()).enumerate() {
        if window == pattern {
            // 4. 计算并存储在目标进程中的绝对地址
            let absolute_address = module_info.base_address + index;
            found_addresses.push(absolute_address);

            // 如果达到了最大查找次数，则提前返回
            if found_addresses.len() >= max_occurrences {
                break;
            }
        }
    }
    
    tracing::info!("Found {} occurrences.", found_addresses.len());
    Ok(found_addresses)
}