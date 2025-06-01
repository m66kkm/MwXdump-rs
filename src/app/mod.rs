//! 应用核心模块
//! 
//! 管理应用的生命周期和核心逻辑

use crate::config::ConfigService;
use crate::errors::Result;

pub mod manager;
pub mod context;

pub use manager::Manager;
pub use context::AppContext;

/// 应用主结构
pub struct App {
    config: ConfigService,
    manager: Manager,
}

impl App {
    /// 创建新的应用实例
    pub fn new(config: ConfigService) -> Result<Self> {
        let manager = Manager::new(&config)?;
        
        Ok(Self {
            config,
            manager,
        })
    }
    
    /// 运行应用
    pub async fn run(self) -> Result<()> {
        self.manager.run().await
    }
}