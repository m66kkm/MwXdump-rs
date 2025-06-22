//! # Windows 句柄 RAII 包装器
//!
//! 提供了一个安全的 Windows HANDLE 包装器，实现了 RAII 模式，
//! 确保句柄在离开作用域时自动释放，防止资源泄漏。

use std::ops::{Deref, DerefMut};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use crate::errors::Result;

/// Windows 句柄的 RAII 包装器
/// 
/// 这个结构体包装了 Windows 的 HANDLE 类型，并实现了 Drop trait
/// 来确保句柄在离开作用域时自动调用 CloseHandle 进行清理。
/// 
/// # 特性
/// - 构造时验证句柄有效性
/// - 自动资源清理（RAII）
/// - 透明访问（通过 Deref/DerefMut）
/// - 调试支持
/// 
/// # 示例
/// ```rust
/// use crate::utils::windows::handle::Handle;
/// use windows::Win32::System::Threading::OpenProcess;
/// 
/// // 创建句柄，如果无效会返回错误
/// let handle = Handle::new(unsafe { OpenProcess(...) })?;
/// 
/// // 可以像原生 HANDLE 一样使用
/// some_winapi_function(*handle);
/// 
/// // 离开作用域时自动调用 CloseHandle
/// ```
#[derive(Debug)]
pub struct Handle(HANDLE);

impl Handle {
    /// 创建一个新的 Handle 包装器
    /// 
    /// # 参数
    /// - `handle`: 要包装的原始 HANDLE
    /// 
    /// # 返回值
    /// - `Ok(Handle)`: 如果句柄有效
    /// - `Err(...)`: 如果句柄无效
    /// 
    /// # 错误
    /// 如果传入的句柄无效（is_invalid() 或等于 INVALID_HANDLE_VALUE），
    /// 将返回从 Win32 错误转换而来的错误。
    pub fn new(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() || handle == INVALID_HANDLE_VALUE {
            Err(windows::core::Error::from_win32().into())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for Handle {
    /// 自动清理句柄资源
    /// 
    /// 当 Handle 离开作用域时，会自动调用此方法。
    /// 如果句柄仍然有效，会调用 CloseHandle 进行清理。
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseHandle(self.0); };
        }
    }
}

impl Deref for Handle {
    type Target = HANDLE;
    
    /// 允许透明访问内部的 HANDLE
    /// 
    /// 这使得 Handle 可以像原生 HANDLE 一样使用，
    /// 例如：`*handle` 或直接传递给需要 HANDLE 的函数。
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Handle {
    /// 允许透明的可变访问内部的 HANDLE
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;

    #[test]
    fn test_invalid_handle_creation() {
        // 测试无效句柄的创建应该失败
        let result = Handle::new(INVALID_HANDLE_VALUE);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_handle_creation_with_null() {
        // 测试空句柄的创建应该失败
        let result = Handle::new(HANDLE::default());
        assert!(result.is_err());
    }
}