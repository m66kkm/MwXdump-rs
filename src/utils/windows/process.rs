use crate::utils::ProcessInfo;
use crate::errors::Result;
use windows::Win32::Foundation::STILL_ACTIVE;
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE}, // CloseHandle 已经不需要，可以移除
        Storage::FileSystem::{
            GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
        },
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        System::{
            ProcessStatus::GetModuleFileNameExW,
            Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
};
use windows_result::BOOL;

use windows::Win32::System::{
    Diagnostics::{
        Debug::ReadProcessMemory,
        ToolHelp::{
            Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        },
    },
    Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
    },
    SystemInformation::{
        GetNativeSystemInfo, PROCESSOR_ARCHITECTURE, PROCESSOR_ARCHITECTURE_AMD64,
        PROCESSOR_ARCHITECTURE_ARM, PROCESSOR_ARCHITECTURE_ARM64, PROCESSOR_ARCHITECTURE_IA64,
        PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
    },
    Threading::{IsWow64Process, PROCESS_QUERY_LIMITED_INFORMATION},
};

// use std::path::PathBuf;
use std::ffi::c_void;

pub fn list_processes(filter: &[&str]) -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();
    // CreateToolhelp32Snapshot 返回 Result<HANDLE>，用 ? 处理错误
    let snapshot_handle: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    // HANDLE 会在离开作用域时自动关闭，无需手动 CloseHandle

    let mut process_entry = PROCESSENTRY32W::default();
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // *** FIX: 使用 .is_ok() 替代 .as_bool() ***
    if unsafe { Process32FirstW(snapshot_handle, &mut process_entry) }.is_ok() {
        loop {
            // 使用 PCWSTR::from_raw 更安全地处理 C 风格的宽字符串
            let process_name = unsafe {
                // szExeFile 是一个 [u16; 260] 数组，它的指针总是有效的
                PCWSTR::from_raw(process_entry.szExeFile.as_ptr()).to_string()?
            };

            if filter
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&process_name))
            {
                tracing::info!(
                    "检测到进程: pid: {}, name: {}",
                    process_entry.th32ProcessID,
                    process_name
                );
                let process_exe_path = get_process_exe_path(process_entry.th32ProcessID)?;
                let file_version_info = get_file_version_info(&process_exe_path)?;
                processes.push(ProcessInfo {
                    parent_pid: process_entry.th32ParentProcessID,
                    pid: process_entry.th32ProcessID,
                    name: process_name,
                    path: Some(process_exe_path), // 初始时路径为 None
                    version: Some(file_version_info), // 初始时版本为 None
                    is_64_bit: get_process_architecture(process_entry.th32ProcessID)? == 8,
                });
            }
            // *** FIX: 使用 .is_ok() 替代 .as_bool() ***
            // 当没有更多进程时，Process32NextW 返回 FALSE，
            // windows crate 将其转换为 Err，所以 .is_ok() 会返回 false，循环正常退出。
            if !unsafe { Process32NextW(snapshot_handle, &mut process_entry) }.is_ok() {
                break;
            }
        }
    } else {
        // 如果连第一个进程都获取失败，说明有错误发生（而不是列表为空）
        // 可以返回一个错误，或者像原逻辑一样返回一个空列表。返回错误更明确。
        // `windows::core::Error::from_win32()` 会获取 GetLastError() 的值。
        return Err(windows::core::Error::from_win32().into());
    }
    tracing::info!("进程列表: {:?}", processes);
    Ok(processes)
}

pub fn get_process_exe_path(pid: u32) -> Result<String> {
    const MAX_PATH_LEN: usize = 1024;
    let mut exe_path_buffer: Vec<u16> = vec![0; MAX_PATH_LEN];

    // OpenProcess 返回 Result<HANDLE>，用 ? 处理错误
    let process_handle: HANDLE =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    // process_handle 会在离开作用域时自动关闭

    // *** FIX: 将参数包装在 Option 中 ***
    // hprocess: Some(process_handle)
    // hmodule: None (等同于传递 NULL，表示获取主可执行文件路径)
    let len = unsafe { GetModuleFileNameExW(Some(process_handle), None, &mut exe_path_buffer) };

    if len == 0 {
        // 如果失败，从 GetLastError() 获取错误信息
        return Err(windows::core::Error::from_win32().into());
    }

    // 根据返回的长度创建字符串，这个长度不包括末尾的 null 字符
    let exe_path = String::from_utf16_lossy(&exe_path_buffer[..len as usize]);
    Ok(exe_path)
}

pub fn get_file_version_info(exe_path: &str) -> Result<String> {
    tracing::debug!("--- 开始获取文件版本 for: [{}] ---", exe_path);

    let wide_path = HSTRING::from(exe_path);

    // 步骤 1: 获取版本信息块的大小
    let mut version_info_size: u32 = 0;
    unsafe {
        // 我们直接调用 GetFileVersionInfoSizeW，因为它不返回 Result，而是直接返回大小
        // 这样可以避免对 0 值的额外处理
        version_info_size = GetFileVersionInfoSizeW(PCWSTR(wide_path.as_ptr()), None);
    }

    if version_info_size == 0 {
        let err = windows::core::Error::from_win32();
        tracing::error!(
            "步骤 1 失败: GetFileVersionInfoSizeW 返回 0. Win32 Error: {}",
            err
        );
        return Err(anyhow::anyhow!(
            "Failed to get file version info size for [{}]. Win32 Error: {}",
            exe_path,
            err
        ));
    }
    tracing::debug!(
        "步骤 1 成功: GetFileVersionInfoSizeW 返回大小: {}",
        version_info_size
    );

    // 步骤 2: 获取版本信息数据
    let mut version_info_buffer: Vec<u8> = vec![0; version_info_size as usize];
    let get_info_result = unsafe {
        GetFileVersionInfoW(
            PCWSTR(wide_path.as_ptr()),
            None,
            version_info_size,
            version_info_buffer.as_mut_ptr() as *mut c_void,
        )
    };

    if let Err(e) = get_info_result {
        tracing::error!(
            "步骤 2 失败: GetFileVersionInfoW 返回错误. Win32 Error: {}",
            e
        );
        return Err(e.into());
    }
    tracing::debug!("步骤 2 成功: GetFileVersionInfoW 执行完毕.");
    // 可以选择性地打印缓冲区的一小部分来检查数据是否被填充
    // tracing::debug!("版本信息缓冲区 (前16字节): {:?}", &version_info_buffer.get(..16));

    // 步骤 3: 查询 VS_FIXEDFILEINFO 结构
    let mut fixed_file_info_ptr: *mut c_void = std::ptr::null_mut(); // 使用 *mut c_void，因为这是 API 的要求
    let mut len: u32 = 0;
    let query_str: [u16; 2] = ['\\' as u16, 0];

    let query_success: BOOL = unsafe {
        VerQueryValueW(
            version_info_buffer.as_ptr() as *const c_void,
            PCWSTR(query_str.as_ptr()),
            &mut fixed_file_info_ptr, // 直接传递 *mut c_void 的地址
            &mut len,
        )
    };

    if !query_success.as_bool() {
        let err = windows::core::Error::from_win32();
        tracing::error!(
            "步骤 3 失败: VerQueryValueW 返回 FALSE. Win32 Error: {}",
            err
        );
        return Err(anyhow::anyhow!(
            "Failed to query VS_FIXEDFILEINFO (VerQueryValueW failed) for [{}]. Win32 Error: {}",
            exe_path,
            err
        ));
    }
    tracing::debug!(
        "步骤 3 成功: VerQueryValueW 返回 TRUE. 指针是否为null: {}, 获取到的长度: {}",
        fixed_file_info_ptr.is_null(),
        len
    );

    // 步骤 4: 检查查询结果
    if fixed_file_info_ptr.is_null() || len == 0 {
        tracing::error!("步骤 4 失败: VerQueryValueW 成功了，但没有返回有效的指针或长度.");
        return Err(anyhow::anyhow!(
            "VS_FIXEDFILEINFO not found or is empty for [{}]",
            exe_path
        ));
    }
    // 检查 len 是否至少是 VS_FIXEDFILEINFO 的大小
    if len < std::mem::size_of::<VS_FIXEDFILEINFO>() as u32 {
        tracing::error!(
            "步骤 4 失败: VerQueryValueW 返回的长度 ({}) 小于 VS_FIXEDFILEINFO 的大小.",
            len
        );
        return Err(anyhow::anyhow!(
            "Returned data length is too small for VS_FIXEDFILEINFO for [{}]",
            exe_path
        ));
    }
    tracing::debug!("步骤 4 成功: VerQueryValueW 执行完毕.");

    // 步骤 5: 转换指针并解析数据
    // 我们现在可以安全地将 *mut c_void 转换为 *mut VS_FIXEDFILEINFO
    let fixed_file_info = unsafe { &*(fixed_file_info_ptr as *const VS_FIXEDFILEINFO) };
    tracing::debug!("步骤 5: 指针转换成功. 准备检查签名.");

    if fixed_file_info.dwSignature != 0xFEEF04BD {
        tracing::error!(
            "步骤 5 失败: 签名无效. 期望 0xFEEF04BD, 得到 {:#X}",
            fixed_file_info.dwSignature
        );
        return Err(anyhow::anyhow!(
            "Invalid VS_FIXEDFILEINFO signature for [{}]",
            exe_path
        ));
    }
    tracing::debug!("步骤 5 成功: 签名有效 (0xFEEF04BD).");

    let major = (fixed_file_info.dwFileVersionMS >> 16) & 0xffff;
    let minor = fixed_file_info.dwFileVersionMS & 0xffff;
    let build = (fixed_file_info.dwFileVersionLS >> 16) & 0xffff;
    let patch = fixed_file_info.dwFileVersionLS & 0xffff;
    let version_string = format!("{}.{}.{}.{}", major, minor, build, patch);

    tracing::info!(
        "--- 文件版本获取完成 for [{}], 版本: {} ---",
        exe_path,
        version_string
    );

    Ok(version_string)
}

/// Determines the pointer size (4 for 32-bit, 8 for 64-bit) for a given process.
pub fn get_process_architecture(pid: u32) -> Result<usize> {
    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? };

    let mut is_wow64 = BOOL::default();
    // IsWow64Process 返回 Result，用 ? 处理错误，值会被写入 is_wow64
    unsafe { IsWow64Process(process_handle, &mut is_wow64)? };

    if is_wow64.as_bool() {
        Ok(4)
    } else {
        let mut system_info = SYSTEM_INFO::default();
        unsafe { GetNativeSystemInfo(&mut system_info) };

        let arch = unsafe { system_info.Anonymous.Anonymous.wProcessorArchitecture };
        match arch {
            PROCESSOR_ARCHITECTURE_AMD64
            | PROCESSOR_ARCHITECTURE_IA64
            | PROCESSOR_ARCHITECTURE_ARM64 => Ok(8),
            PROCESSOR_ARCHITECTURE_INTEL | PROCESSOR_ARCHITECTURE_ARM => Ok(4),
            // FIX: 使用 {:?} 格式化
            arch_val => Err(anyhow::anyhow!(
                "Unknown or unsupported processor architecture: {:?}",
                arch_val
            )),
        }
    }
}

/// 检查指定 PID 的进程是否仍在运行。
/// 本函数使用 `windows` crate 实现。
///
/// # Arguments
/// * `pid` - 要检查的进程的 ID。
///
/// # Returns
/// 如果进程正在运行，返回 `true`；否则（进程不存在、无权限、已退出）返回 `false`。
pub fn is_process_running(pid: &u32) -> bool {
    //检查 pid 是否为 0，因为 0 通常表示系统进程或无效 PID。
    // 如果 pid 为 0，直接返回 false，因为无效的 PID 不可能对应一个正在运行的进程。
    // 这里的 pid 是引用类型，所以需要解引用才能获取实际的值。
    if *pid == 0 {
        return false;
    }

    // unsafe 块是必需的，因为我们正在调用 Windows API (FFI)
    unsafe {
        // 1. 调用 `windows` crate 的 OpenProcess 函数，尝试获取进程句柄。
        //    该函数返回一个 Result，我们需要处理它。
        if let Ok(process_handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, *pid) {
            // 2. 声明一个 u32 类型的变量来接收退出码。
            let mut exit_code: u32 = 0;

            // 3. 调用 `windows` crate 的 GetExitCodeProcess 函数。
            let result = GetExitCodeProcess(process_handle, &mut exit_code);

            // 4. 调用 `windows` crate 的 CloseHandle 函数，关闭句柄以释放资源。
            CloseHandle(process_handle);

            // 5. 将 u32 退出码与 `windows` crate 提供的 STILL_ACTIVE 常量直接比较。
            result.is_ok() && exit_code == STILL_ACTIVE.0 as u32
        } else {
            // 如果 OpenProcess 返回 Err，意味着进程不存在或我们没有权限访问。
            // 在这种情况下，我们认为它“没有运行”。
            false
        }
    }
}
