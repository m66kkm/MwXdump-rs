//! 群聊数据模型

use serde::{Deserialize, Serialize};

/// 群聊结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRoom {
    pub chatroom_name: String,
    pub display_name: Option<String>,
    pub member_count: i32,
}

impl ChatRoom {
    pub fn new(chatroom_name: String) -> Self {
        Self {
            chatroom_name,
            display_name: None,
            member_count: 0,
        }
    }
}