use windows_result::BOOL;
use crate::errors::Result;
use std::ffi::c_void;
use windows::{
    core::PCWSTR,
    Win32::{
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
                OpenProcess, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ,
            },
        },
    },
};

/// Reads a region of memory from a specified process.
pub fn read_process_memory(pid: u32, address: usize, size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    let process_handle = unsafe { OpenProcess(PROCESS_VM_READ, false, pid)? };
    
    let mut buffer: Vec<u8> = vec![0; size];
    let mut bytes_read: usize = 0;

    // ReadProcessMemory 返回 Result，可以直接用 ?
    unsafe {
        ReadProcessMemory(
            process_handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            Some(&mut bytes_read),
        )?
    };

    buffer.truncate(bytes_read);
    Ok(buffer)
}

/// Gets the base address of a specific module loaded in a process.
pub fn get_module_base_address(pid: u32, module_name: &str) -> Result<usize> {
    let snapshot_handle =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)? };

    let mut module_entry = MODULEENTRY32W::default();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    // FIX: 使用 .is_ok()
    if unsafe { Module32FirstW(snapshot_handle, &mut module_entry) }.is_ok() {
        loop {
            let current_module_name =
                unsafe { PCWSTR::from_raw(module_entry.szModule.as_ptr()).to_string()? };

            if current_module_name.eq_ignore_ascii_case(module_name) {
                return Ok(module_entry.modBaseAddr as usize);
            }

            // FIX: 使用 .is_ok()
            if !unsafe { Module32NextW(snapshot_handle, &mut module_entry) }.is_ok() {
                break;
            }
        }
    } else {
        return Err(windows::core::Error::from_win32().into());
    }

    Err(anyhow::anyhow!("Module '{}' not found in PID {}", module_name, pid))
}

/// Searches for a byte pattern within a given memory region of a process.
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

    let process_handle =
        unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)? };

    let mut found_addresses = Vec::new();
    let mut current_address = start_address;
    let mut buffer = vec![0u8; 4096 * 2];

    while current_address < end_address && found_addresses.len() < max_occurrences {
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        let query_result = unsafe {
            VirtualQueryEx(
                process_handle,
                Some(current_address as *const c_void),
                &mut mem_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if query_result == 0 {
            break;
        }

        let region_base = mem_info.BaseAddress as usize;
        let region_end = region_base + mem_info.RegionSize;

        let is_readable = mem_info.State == MEM_COMMIT
            && (mem_info.Protect == PAGE_READWRITE
                || mem_info.Protect == PAGE_READONLY
                || mem_info.Protect == PAGE_EXECUTE_READ
                || mem_info.Protect == PAGE_EXECUTE_READWRITE);

        if is_readable {
            let mut address_to_scan = current_address.max(region_base);

            while address_to_scan < region_end && found_addresses.len() < max_occurrences {
                let bytes_to_read = std::cmp::min(buffer.len(), region_end - address_to_scan);
                if bytes_to_read == 0 {
                    break;
                }

                let mut bytes_read = 0;
                // ReadProcessMemory 返回 Result，可以直接用 .is_ok() 判断
                let read_result = unsafe {
                    ReadProcessMemory(
                        process_handle,
                        address_to_scan as *const c_void,
                        buffer.as_mut_ptr() as *mut c_void,
                        bytes_to_read,
                        Some(&mut bytes_read),
                    )
                };

                if read_result.is_ok() && bytes_read > 0 {
                    let actual_buffer = &buffer[..bytes_read];
                    for (i, window) in actual_buffer.windows(pattern.len()).enumerate() {
                        if window == pattern {
                            found_addresses.push(address_to_scan + i);
                            if found_addresses.len() >= max_occurrences {
                                break;
                            }
                        }
                    }
                }

                address_to_scan += bytes_read;
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