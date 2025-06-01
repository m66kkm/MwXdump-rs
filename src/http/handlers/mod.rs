//! HTTP处理器模块

use axum::{Json, response::Result};
use serde_json::Value;

/// API处理器
pub struct ApiHandlers {
    // 占位符实现
}

impl ApiHandlers {
    pub fn new() -> Self {
        Self {}
    }
    
    pub async fn get_messages(&self) -> Result<Json<Value>> {
        Ok(Json(serde_json::json!({
            "messages": [],
            "total": 0
        })))
    }
    
    pub async fn get_contacts(&self) -> Result<Json<Value>> {
        Ok(Json(serde_json::json!({
            "contacts": [],
            "total": 0
        })))
    }
}