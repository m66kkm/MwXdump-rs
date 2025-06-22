use anyhow::bail;
use windows::{
    core::PCWSTR,
    Win32::{
        System::{
            Diagnostics::{
                ToolHelp::{
                    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
                },
            },

        },
    },
};

use crate::errors::Result;
use super::handle::Handle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
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

// --- 私有辅助函数 ---

fn module_name_from_entry(entry: &MODULEENTRY32W) -> Result<String> {
    Ok(unsafe { PCWSTR::from_raw(entry.szModule.as_ptr()).to_string()? })
}