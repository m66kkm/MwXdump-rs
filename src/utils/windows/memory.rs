//! # Windows 进程内存工具集
//!
//! 提供了一系列与 Windows 进程内存交互的实用函数。
//! ... (其他文档)

use std::{
    ffi::c_void,
    ops::{Deref, DerefMut},
    // FIX: 导入 LazyLock 用于懒初始化 static 变量
    sync::LazyLock,
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
                PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            },
            Threading::{
                OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
};

// --- 公共类型和常量 ---

pub type Result<T> = crate::Result<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
}

const SCAN_BUFFER_SIZE: usize = 4096 * 2;

// FIX: 使用 LazyLock 来包装 static 变量。
// 原因是 `|` (BitOr) 操作符对于这些 windows-rs 类型不是 `const fn`，
// 不能在编译时用于初始化 static 或 const。
// LazyLock 会在第一次访问时，在运行时执行一次初始化闭包。
static PROCESS_READ_PERMISSIONS: LazyLock<PROCESS_ACCESS_RIGHTS> =
    LazyLock::new(|| PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);

static READABLE_PAGE_PROTECTIONS: LazyLock<PAGE_PROTECTION_FLAGS> = LazyLock::new(|| {
    PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
});

// --- 私有 RAII 句柄包装器 ---
#[derive(Debug)]
struct Handle(HANDLE);

impl Handle {
    fn new(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() || handle == INVALID_HANDLE_VALUE {
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

// --- 核心内存操作函数 ---

pub fn read_process_memory(pid: u32, address: usize, size: usize) -> Result<Vec<u8>> {
    let process_handle = Handle::new(unsafe { OpenProcess(PROCESS_VM_READ, false, pid)? })?;
    read_process_memory_with_handle(*process_handle, address, size)
}

fn read_process_memory_with_handle(
    handle: HANDLE,
    address: usize,
    size: usize,
) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;
    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            Some(&mut bytes_read),
        )?;
    }
    buffer.truncate(bytes_read);
    Ok(buffer)
}

pub fn get_module_info(pid: u32, module_name: &str) -> Result<ModuleInfo> {
    let snapshot_handle = Handle::new(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?
    })?;

    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    unsafe { Module32FirstW(*snapshot_handle, &mut module_entry)? };

    loop {
        let current_module_name = module_name_from_entry(&module_entry)?;
        if current_module_name.eq_ignore_ascii_case(module_name) {
            return Ok(ModuleInfo {
                base_address: module_entry.modBaseAddr as usize,
                size: module_entry.modBaseSize as usize,
            });
        }
        if unsafe { Module32NextW(*snapshot_handle, &mut module_entry) }.is_err() {
            break;
        }
    }

    bail!(crate::errors::SystemError::ModuleInfoMissing {
        value: module_name.to_string(),
        pid,
    });
}

pub fn read_module_memory(pid: u32, module_name: &str) -> Result<Vec<u8>> {
    let module_info = get_module_info(pid, module_name)?;
    tracing::debug!(
        "Found module '{}' at base {:#x} with size {} bytes.",
        module_name, module_info.base_address, module_info.size
    );
    read_process_memory(pid, module_info.base_address, module_info.size)
}

pub fn search_memory_for_pattern(
    pid: u32,
    pattern: &[u8],
    start_address: usize,
    end_address: usize,
    max_occurrences: usize,
) -> Result<Vec<usize>> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }

    // FIX: 使用 `*` 解引用 LazyLock<T> 来获取其内部值
    let process_handle = Handle::new(unsafe { OpenProcess(*PROCESS_READ_PERMISSIONS, false, pid)? })?;
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
        } == 0
        {
            break;
        }

        let region_base = mem_info.BaseAddress as usize;
        let region_end = region_base.saturating_add(mem_info.RegionSize);

        // FIX: 使用 `*` 解引用 LazyLock<T>，并与零值比较
        let is_readable = (mem_info.State == MEM_COMMIT)
            && (mem_info.Protect & *READABLE_PAGE_PROTECTIONS) != PAGE_PROTECTION_FLAGS(0);

        if is_readable {
            let mut scan_ptr = current_address.max(region_base);
            while scan_ptr < region_end && found_addresses.len() < max_occurrences {
                let overlap_size = if previous_read_size > 0 { pattern.len() - 1 } else { 0 };
                if overlap_size > 0 {
                    buffer.copy_within((previous_read_size - overlap_size)..previous_read_size, 0);
                }

                let bytes_to_read = SCAN_BUFFER_SIZE.min(region_end - scan_ptr);
                let mut bytes_read = 0;
                
                let read_result = unsafe {
                    ReadProcessMemory(
                        *process_handle,
                        scan_ptr as *const c_void,
                        buffer.as_mut_ptr().add(overlap_size) as *mut c_void,
                        bytes_to_read,
                        Some(&mut bytes_read),
                    )
                };

                if read_result.is_ok() {
                    if bytes_read > 0 {
                        let search_area = &buffer[..overlap_size + bytes_read];
                        for (i, window) in search_area.windows(pattern.len()).enumerate() {
                            if window == pattern {
                                let match_addr = (scan_ptr - overlap_size) + i;
                                if found_addresses.last().map_or(true, |&last| last < match_addr) {
                                    found_addresses.push(match_addr);
                                    if found_addresses.len() >= max_occurrences {
                                        return Ok(found_addresses);
                                    }
                                }
                            }
                        }
                        previous_read_size = overlap_size + bytes_read;
                        scan_ptr += bytes_read;
                    } else {
                        break;
                    }
                } else {
                    tracing::warn!("Failed to read memory at {:#x}, skipping region.", scan_ptr);
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
// In your memory.rs file

pub fn search_module_for_pattern(
    pid: u32,
    module_name: &str,
    pattern: &[u8],
    max_occurrences: usize,
) -> Result<Vec<usize>> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }
    tracing::info!(
        "Searching for pattern in module '{}' of process {}...",
        module_name,
        pid
    );

    // 1. 获取模块的边界信息
    let module_info = get_module_info(pid, module_name)?;
    let start_address = module_info.base_address;
    let end_address = start_address.saturating_add(module_info.size);

    tracing::info!(
        "Module '{}' found. Scanning from {:#x} to {:#x}.",
        module_name,
        start_address,
        end_address
    );

    // 2. 调用更底层的、逐个内存区域扫描的函数。
    // 这个函数能够处理模块内部可能存在的不可读内存页。
    let found_addresses =
        search_memory_for_pattern(pid, pattern, start_address, end_address, max_occurrences)?;

    tracing::info!(
        "Found {} occurrences in module '{}'.",
        found_addresses.len(),
        module_name
    );
    Ok(found_addresses)
}


// --- 私有辅助函数 ---

fn module_name_from_entry(entry: &MODULEENTRY32W) -> Result<String> {
    Ok(unsafe { PCWSTR::from_raw(entry.szModule.as_ptr()).to_string()? })
}