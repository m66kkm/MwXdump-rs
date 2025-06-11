use anyhow::{anyhow, Result};
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ, REG_SZ, REG_VALUE_TYPE,
};

// 修正：重命名函数以匹配您项目中的调用，并修正了 w! 宏的错误用法
pub fn get_string_from_registry(
    hkey_root: HKEY,
    sub_key_path: &str, // 接受 &str
    value_name: &str,   // 接受 &str
) -> Result<String> {
    let mut hkey = HKEY::default();

    // 修正：使用 PCWSTR::from_raw 来正确传递字符串
    let wide_sub_key_path: Vec<u16> = sub_key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_value_name: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    let status_open = unsafe {
        RegOpenKeyExW(
            hkey_root,
            PCWSTR::from_raw(wide_sub_key_path.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hkey,
        )
    };
    status_open.ok().map_err(|e| {
        anyhow!("Failed to open registry key '{}'. {}", sub_key_path, e)
    })?;

    let mut data_type = REG_VALUE_TYPE::default();
    let mut buffer_size: u32 = 0;

    let status_query_size = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(wide_value_name.as_ptr()),
            None,
            Some(&mut data_type),
            None,
            Some(&mut buffer_size),
        )
    };
    status_query_size.ok().map_err(|e| {
        anyhow!(
            "Failed to query size of registry value '{}'. {}",
            value_name,
            e
        )
    })?;

    if data_type.0 != REG_SZ.0 {
        return Err(anyhow!(
            "Registry value '{}' is not a string (REG_SZ), but type {}.",
            value_name,
            data_type.0
        ));
    }

    if buffer_size == 0 {
        return Ok(String::new());
    }

    let mut value_buffer: Vec<u16> = vec![0u16; (buffer_size / 2) as usize];
    let mut actual_buffer_size = buffer_size;

    let status_query_value = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(wide_value_name.as_ptr()),
            None,
            None,
            Some(value_buffer.as_mut_ptr() as *mut u8),
            Some(&mut actual_buffer_size),
        )
    };
    status_query_value.ok().map_err(|e| {
        anyhow!("Failed to query value of registry key '{}'. {}", value_name, e)
    })?;

    let num_u16s = (actual_buffer_size / 2) as usize;
    let end_idx = if num_u16s > 0 && value_buffer[num_u16s - 1] == 0 {
        num_u16s - 1
    } else {
        num_u16s
    };

    Ok(String::from_utf16_lossy(&value_buffer[..end_idx]))
}
