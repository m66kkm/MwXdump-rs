//! 消息数据模型

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// 消息结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub seq: i64,
    pub time: DateTime<Utc>,
    pub talker: String,
    pub talker_name: Option<String>,
    pub is_chatroom: bool,
    pub sender: String,
    pub sender_name: Option<String>,
    pub is_self: bool,
    pub msg_type: i64,
    pub sub_type: i64,
    pub content: String,
}

impl Message {
    pub fn new() -> Self {
        Self {
            seq: 0,
            time: Utc::now(),
            talker: String::new(),
            talker_name: None,
            is_chatroom: false,
            sender: String::new(),
            sender_name: None,
            is_self: false,
            msg_type: 1,
            sub_type: 0,
            content: String::new(),
        }
    }
}