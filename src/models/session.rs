//! 会话数据模型

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// 会话结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub username: String,
    pub last_message_time: DateTime<Utc>,
    pub unread_count: i32,
}

impl Session {
    pub fn new(username: String) -> Self {
        Self {
            username,
            last_message_time: Utc::now(),
            unread_count: 0,
        }
    }
}