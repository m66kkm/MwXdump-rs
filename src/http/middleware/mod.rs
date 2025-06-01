//! HTTP中间件模块

use axum::{
    http::{Request, Response},
    middleware::Next,
    body::Body,
};

/// CORS中间件
pub async fn cors_middleware(
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let response = next.run(request).await;
    
    // TODO: 实现CORS逻辑
    response
}

/// 日志中间件
pub async fn logging_middleware(
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    println!("HTTP请求: {} {}", request.method(), request.uri());
    
    let response = next.run(request).await;
    
    println!("HTTP响应: {}", response.status());
    response
}