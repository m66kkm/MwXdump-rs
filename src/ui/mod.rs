//! Terminal UI模块

pub mod components;

use crate::errors::Result;

/// UI应用
pub struct UiApp {
    // 占位符实现
}

impl UiApp {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
    
    pub async fn run(self) -> Result<()> {
        // 占位符实现
        println!("Terminal UI 启动中...");
        Ok(())
    }
}