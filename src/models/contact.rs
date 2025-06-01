//! 联系人数据模型

use serde::{Deserialize, Serialize};

/// 联系人结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub username: String,
    pub nickname: Option<String>,
    pub remark: Option<String>,
    pub avatar: Option<String>,
}

impl Contact {
    pub fn new(username: String) -> Self {
        Self {
            username,
            nickname: None,
            remark: None,
            avatar: None,
        }
    }
}