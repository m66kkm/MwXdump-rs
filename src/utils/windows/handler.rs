use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use std::ops::{Deref};
use crate::errors::Result; 

pub struct Handle(HANDLE);

impl Handle {
    pub fn new(handle: HANDLE) -> Result<Self> {
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