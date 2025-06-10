use crate::errors::{Result, MwxDumpError};

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// 微信版本信息
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WeChatVersion {
    /// 3.x版本
    V3x { exact: String },
    /// 4.0版本
    V4x { exact: String },
    /// 未知版本
    Unknown,
}


impl WeChatVersion {
    /// 获取版本字符串
    pub fn version_string(&self) -> &str {
        match self {
            WeChatVersion::V3x { exact } => exact,
            WeChatVersion::V4x { exact } => exact,
            WeChatVersion::Unknown => "unknown",
        }
    }
   
    /// 是否为3.x版本
    pub fn is_v3x(&self) -> bool {
        matches!(self, WeChatVersion::V3x { .. })
    }
    
    /// 是否为4.x版本
    pub fn is_v4x(&self) -> bool {
        matches!(self, WeChatVersion::V4x { .. })
    }
}

// 现在，我们来实现解析逻辑
impl FromStr for WeChatVersion {
    // 这里的 Err 类型可以使用我们自定义的错误类型
    type Err = MwxDumpError;

    fn from_str(s: &str) -> Result<Self> {
        // 在这里你应该放入你真实的解析逻辑
        // 下面是一个简化的例子
        if s.starts_with("3.") {
            Ok(WeChatVersion::V3x { exact: s.to_string() })
        } else if s.starts_with("4.") {
            Ok(WeChatVersion::V4x { exact: s.to_string() })
        } else {
            // 如果解析失败，返回我们的自定义错误
            Err(MwxDumpError::InvalidVersion(s.to_string()))
        }
    }
}
