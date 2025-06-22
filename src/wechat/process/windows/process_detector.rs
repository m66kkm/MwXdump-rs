//! Windows平台的微信进程检测实现

use super::{ProcessDetector, WeChatVersion, WechatProcessInfo};
// use crate::errors::{Result, WeChatError};
use crate::errors::Result;
use crate::utils::windows as utils_windows;
use async_trait::async_trait;
use chrono::Utc;
use core::time;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};
use windows::Win32::System::Registry::HKEY_CURRENT_USER;

impl super::WindowsProcessDetector {
    const MIN_ADDRESS: usize = 0x10000; // Process space usually starts from 0x10000
    const MAX_ADDRESS_32: usize = 0x7FFFFFFF; // 32-bit process space limit
    const MAX_ADDRESS_64: usize = 0x00007FFFFFFFFFFF;

    pub fn create_wxwork_detector() -> Result<Self> {
        Ok(Self {
            // 直接克隆 Lazy<Vec> 里的 Vec。这非常高效。
            wechat_process_names: super::WXWORK_PROCESS_NAMES.clone(),
        })
    }

    pub fn create_wechat_detector() -> Result<Self> {
        Ok(Self {
            // .clone() 会隐式地解引用 Lazy，然后调用 Vec::clone()
            wechat_process_names: super::WECHAT_PROCESS_NAMES.clone(),
        })
    }

    /// 验证进程版本是否有效（包含数字和点号，非Unknown）
    fn validate_process_version(&self, process: &WechatProcessInfo) -> bool {
        match &process.version {
            WeChatVersion::V3x { exact } | WeChatVersion::V4x { exact } => {
                exact.chars().any(|c| c.is_ascii_digit()) && exact.contains('.')
            }
            WeChatVersion::Unknown => false,
        }
    }

    // 这是一个私有的、同步的、阻塞的辅助方法。
    // 必须保证只在 spawn_blocking 中调用它。
    fn find_wechat_data_directory(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>> {
        // 策略1: 尝试从注册表获取并验证
        if let Ok(reg_path_str) = utils_windows::registry::get_string_from_registry(
            HKEY_CURRENT_USER,
            super::WECHAT_REG_KEY_PATH,
            super::WECHAT_FILES_VALUE_NAME,
        ) {
            let candidate_dir = PathBuf::from(reg_path_str);
            // 检查目录是否存在，并且在内存中验证通过
            if candidate_dir.is_dir() && self.is_datadir_valid_in_memory(process, &candidate_dir)? {
                tracing::info!(
                    "PID {}: 通过注册表找到并验证了数据目录: {:?}",
                    process.pid,
                    candidate_dir
                );
                return Ok(Some(candidate_dir)); // 验证成功，立即返回
            }
        }

        // 策略2: 尝试从 xwechat 配置文件获取并验证
        if let Ok(Some(candidate_dir)) = self.find_from_xwechat_config() {
            // 同样，检查目录是否存在并进行内存验证
            if candidate_dir.is_dir() && self.is_datadir_valid_in_memory(process, &candidate_dir)? {
                tracing::info!(
                    "通过PID {}: 验证了数据目录: {:?} 有效",
                    process.pid,
                    candidate_dir
                );
                return Ok(Some(candidate_dir)); // 验证成功，立即返回
            }
        }

        // 策略3: (TBD) 最后尝试内存路径搜索方法
        // ...

        // 所有策略都失败后
        tracing::warn!("PID {}: 未能找到微信数据目录", process.pid);
        Ok(None)
    }

    /// 辅助函数：检查候选的数据目录是否真实有效（通过在进程内存中搜索路径字符串）。
    /// 这个函数封装了所有验证逻辑。
    fn is_datadir_valid_in_memory(
        &self,
        process: &WechatProcessInfo,
        data_dir: &PathBuf,
    ) -> Result<bool> {
        // 修复安全问题：安全地将 PathBuf 转换为 &str
        let dir_str = match data_dir.to_str() {
            Some(s) => s,
            None => {
                tracing::debug!(
                    "PID {}: 数据目录路径 {:?} 包含无效UTF-8字符, 无法进行内存验证",
                    process.pid,
                    data_dir
                );
                return Ok(false); // 路径无效，视为验证失败
            }
        };

        let end_address = if process.is_64_bit{
            Self::MAX_ADDRESS_64
        } else {
            Self::MAX_ADDRESS_32
        };

        match utils_windows::memory::search_memory_for_pattern(
            process.pid,
            dir_str.as_bytes(),
            Self::MIN_ADDRESS,
            end_address,
            1,
        ) {
            Ok(location) => {
                if !location.is_empty() {
                    // 修复日志信息，并正确处理找到的情况
                    tracing::debug!(
                        "PID {}: 在内存中成功验证数据目录 '{}'，所在位置为: {:?}",
                        process.pid,
                        dir_str,
                        location
                    );
                    Ok(true) // 找到了，验证成功
                } else {
                    // 修复未找到的逻辑
                    tracing::debug!(
                        "PID {}: 数据目录 '{}' 未在进程内存中找到，判定为无效",
                        process.pid,
                        dir_str
                    );
                    Ok(false) // 没找到，验证失败
                }
            }
            Err(e) => {
                // 改进错误处理：将搜索本身的错误传递出去
                tracing::error!("PID {}: 在内存中验证数据目录时发生错误: {}", process.pid, e);
                // 这里返回 Err，而不是 Ok(false)，因为这意味着验证操作本身失败了，
                // 而不是“验证了但结果是假的”。调用者可以决定如何处理这个错误。
                Err(e.into())
            }
        }
    }

    /// 从 xwechat 配置文件中查找数据目录
    fn find_from_xwechat_config(&self) -> Result<Option<PathBuf>> {
        // 1. 获取用户主目录
        let user_dir = utils_windows::file::get_user_profile_dir()?;

        // 2. 构建 xwechat config 路径
        let config_dir = user_dir.join("AppData\\Roaming\\Tencent\\xwechat\\config");

        if !utils_windows::file::check_directory_exists(&config_dir) {
            tracing::debug!("xwechat 配置目录不存在: {:?}", config_dir);
            return Ok(None);
        }

        // 3. 获取所有 ini 文件
        let ini_files = utils_windows::file::list_files(&config_dir, "ini", true)?;

        if ini_files.is_empty() {
            tracing::debug!("xwechat 配置目录中没有找到 ini 文件");
            return Ok(None);
        }

        // 4. 读取并解析 ini 文件，收集有效的数据目录
        let mut potential_dirs: Vec<(PathBuf, SystemTime)> = Vec::new();

        for ini_file in ini_files {
            match utils_windows::file::read_file_content(&ini_file) {
                Ok(content) => {
                    // 将字节数组转换为字符串
                    if let Ok(content_str) = String::from_utf8(content) {
                        let content_str = content_str.trim();
                        if !content_str.is_empty() {
                            let dir_path = PathBuf::from(content_str);
                            if let Ok(modified_time) =
                                utils_windows::file::get_file_modified_time(&ini_file)
                            {
                                tracing::debug!(
                                    "找到潜在的数据目录: {:?} (来自 {:?})",
                                    dir_path,
                                    ini_file
                                );
                                potential_dirs.push((dir_path, modified_time));
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("读取 ini 文件失败 {:?}: {}", ini_file, e);
                }
            }
        }

        if potential_dirs.is_empty() {
            tracing::debug!("没有找到有效的数据目录配置");
            return Ok(None);
        }

        // 5. 按修改时间排序（最新的在前）
        potential_dirs.sort_by(|a, b| b.1.cmp(&a.1));

        // 6. 验证每个潜在目录
        for (base_dir, _) in potential_dirs {
            if let Some(wxid_dir) = self.validate_wechat_data_directory(&base_dir)? {
                return Ok(Some(wxid_dir));
            }
        }

        Ok(None)
    }

    /// 验证微信数据目录
    /// 检查 base_dir\xwechat_files\wxid_* 格式的目录是否存在
    fn validate_wechat_data_directory(&self, base_dir: &Path) -> Result<Option<PathBuf>> {
        let xwechat_files_dir = base_dir.join("xwechat_files");

        if !utils_windows::file::check_directory_exists(&xwechat_files_dir) {
            tracing::debug!("xwechat_files 目录不存在: {:?}", xwechat_files_dir);
            return Ok(None);
        }

        // 查找以 wxid_ 开头的目录
        let wxid_dirs =
            utils_windows::file::find_directories_with_prefix(&xwechat_files_dir, "wxid_")?;

        // 如果找到了 wxid_ 目录，返回第一个
        if let Some(wxid_dir) = wxid_dirs.first() {
            tracing::info!("通过xwechat_files，找到有效的微信数据目录: {:?}", wxid_dir);
            return Ok(Some(wxid_dir.clone()));
        }

        tracing::debug!("在 {:?} 中未找到 wxid_ 开头的目录", xwechat_files_dir);
        Ok(None)
    }
}

#[async_trait]
impl ProcessDetector for super::WindowsProcessDetector {
    async fn detect_processes(&self) -> Result<Vec<WechatProcessInfo>> {
        // &self 依然是 'life0
        tracing::info!("开始检测微信进程...");

        // 我们需要克隆 self 所指向的数据，而不是克隆引用本身。
        // `self` 是 `&WindowsProcessDetector`，所以 `self.clone()` 会调用
        // `WindowsProcessDetector` 的 `Clone` 实现，创建一个全新的实例。
        // `detector` 的类型现在是 `WindowsProcessDetector` (owned value), 不是 `&WindowsProcessDetector`。
        let detector = self.clone();

        let detected_processes =
            tokio::task::spawn_blocking(move || -> Result<Vec<WechatProcessInfo>> {
                // `move` 关键字现在移动的是 `detector` 这个拥有所有权的实例，
                // 它的生命周期是 'static，因为它不依赖任何外部引用。

                // ... (闭包内部的其他代码保持不变) ...
                let processes =
                    utils_windows::process::list_processes(&detector.wechat_process_names, true)?;

                let wechat_processes = processes
                    .into_iter()
                    // ... (iterator chain) ...
                    .filter_map(|p| match WechatProcessInfo::new(p) {
                        Ok(mut wechat_process) => {
                            if let Ok(Some(data_dir)) =
                                detector.find_wechat_data_directory(&wechat_process)
                            {
                                wechat_process.data_dir = Some(data_dir);
                            }
                            Some(Ok(wechat_process))
                        }
                        Err(e) => {
                            warn!("创建 WechatProcessInfo 失败: {}", e);
                            None
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;

                Ok(wechat_processes)
            })
            .await??;

        tracing::debug!(
            "阻塞任务完成，成功检测到 {} 个微信主进程",
            detected_processes.len()
        );
        Ok(detected_processes)
    }

    // async fn get_process_info(&self, pid: u32) -> Result<Option<WechatProcessInfo>> {
    //     let processes = self.detect_processes().await?;
    //     Ok(processes.into_iter().find(|p| p.pid == pid))
    // }

    // async fn detect_version(&self, exe_path: &PathBuf) -> Result<WeChatVersion> {
    //     self.detect_version_from_path(exe_path).await
    // }

    // async fn locate_data_dir(&self, process: &WechatProcessInfo) -> Result<Option<PathBuf>> {
    //     self.find_data_directory(process).await
    // }
}
