//! 负责处理文件和目录的解密操作

use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::errors::WeChatError;
use crate::wechat::decrypt::{
    create_decryptor,
    decrypt_validator::KeyValidator,
    DecryptVersion,
};

/// 解密处理器
///
/// 负责处理微信数据库文件的解密操作，支持单文件和批量目录解密。
/// 提供并发处理能力和密钥验证功能。
pub struct DecryptionProcessor {
    /// 输入文件或目录路径
    input_path: PathBuf,
    /// 输出文件或目录路径
    output_path: PathBuf,
    /// 解密密钥字节数组
    key: Vec<u8>,
    /// 并发线程数量
    threads: usize,
    /// 是否仅验证密钥而不执行解密
    validate_only: bool,
}

impl DecryptionProcessor {
    /// 创建新的解密处理器实例
    ///
    /// # 参数
    ///
    /// * `input_path` - 输入文件或目录的路径
    /// * `output_path` - 输出文件或目录的路径
    /// * `key` - 解密密钥的字节数组
    /// * `threads` - 可选的并发线程数，如果为 None 则使用 CPU 核心数
    /// * `validate_only` - 是否仅验证密钥而不执行实际解密
    ///
    /// # 返回值
    ///
    /// 返回配置好的 `DecryptionProcessor` 实例
    ///
    /// # 示例
    ///
    /// ```rust
    /// use std::path::PathBuf;
    ///
    /// let processor = DecryptionProcessor::new(
    ///     PathBuf::from("/path/to/input"),
    ///     PathBuf::from("/path/to/output"),
    ///     vec![0x12, 0x34, 0x56, 0x78], // 示例密钥
    ///     Some(4), // 使用4个线程
    ///     false    // 执行实际解密
    /// );
    /// ```
    pub fn new(
        input_path: PathBuf,
        output_path: PathBuf,
        key: Vec<u8>,
        threads: Option<usize>,
        validate_only: bool,
    ) -> Self {
        let thread_count = threads.unwrap_or_else(num_cpus::get);
        Self {
            input_path,
            output_path,
            key,
            threads: thread_count,
            validate_only,
        }
    }

    /// 执行解密操作
    ///
    /// 根据输入路径的类型（文件或目录）自动选择相应的处理方式：
    /// - 如果是文件，执行单文件解密
    /// - 如果是目录，执行批量目录解密
    ///
    /// # 返回值
    ///
    /// * `Ok(())` - 解密操作成功完成
    /// * `Err(...)` - 解密过程中发生错误
    ///
    /// # 错误
    ///
    /// 当输入路径既不是文件也不是目录时，返回 `WeChatError::DecryptionFailed`
    ///
    /// # 示例
    ///
    /// ```rust
    /// # use anyhow::Result;
    /// # async fn example() -> Result<()> {
    /// let processor = DecryptionProcessor::new(/* ... */);
    /// processor.execute().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn execute(&self) -> Result<()> {
        if self.input_path.is_file() {
            self.handle_single_file_decrypt().await
        } else if self.input_path.is_dir() {
            self.handle_directory_decrypt().await
        } else {
            Err(WeChatError::DecryptionFailed(format!(
                "输入路径既不是文件也不是目录: {:?}",
                self.input_path
            ))
            .into())
        }
    }

    /// 处理单文件解密
    ///
    /// 对单个微信数据库文件执行解密操作。首先验证密钥并检测版本，
    /// 然后根据配置决定是仅验证还是执行实际解密。
    ///
    /// # 处理流程
    ///
    /// 1. 创建密钥验证器并自动检测版本
    /// 2. 如果是验证模式，验证成功后直接返回
    /// 3. 如果是解密模式，创建输出目录并执行解密
    ///
    /// # 返回值
    ///
    /// * `Ok(())` - 单文件处理成功
    /// * `Err(...)` - 处理过程中发生错误
    ///
    /// # 错误
    ///
    /// - 密钥验证失败
    /// - 版本检测失败
    /// - 文件解密失败
    /// - 输出目录创建失败
    async fn handle_single_file_decrypt(&self) -> Result<()> {
        info!("📁 单文件解密模式: {:?}", self.input_path);

        let validator = KeyValidator::new();
        let version = determine_version(&validator, &self.input_path, &self.key).await?;

        if self.validate_only {
            info!("✅ 密钥验证成功！版本: {:?}", version);
            return Ok(());
        }

        if let Some(parent) = self.output_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await?;
            }
        }

        decrypt_single_file(&self.input_path, &self.output_path, &self.key, version).await
    }

    /// 处理目录批量解密
    ///
    /// 对指定目录下的所有微信数据库文件执行批量解密操作。
    /// 支持递归搜索子目录，并使用多线程并发处理以提高效率。
    ///
    /// # 处理流程
    ///
    /// 1. 验证和创建输出目录
    /// 2. 递归收集所有 .db 文件
    /// 3. 如果是验证模式，仅对第一个文件进行密钥验证
    /// 4. 如果是解密模式，使用信号量控制并发数量，并行处理所有文件
    /// 5. 统计处理结果并输出性能报告
    ///
    /// # 并发处理
    ///
    /// - 使用 `Semaphore` 控制最大并发数
    /// - 使用 `AtomicUsize` 统计成功和失败数量
    /// - 使用 `buffer_unordered` 实现异步并发流处理
    ///
    /// # 返回值
    ///
    /// * `Ok(())` - 批量处理成功完成
    /// * `Err(...)` - 处理过程中发生错误
    ///
    /// # 错误
    ///
    /// - 输出路径不是目录
    /// - 文件收集失败
    /// - 密钥验证失败（验证模式）
    async fn handle_directory_decrypt(&self) -> Result<()> {
        info!("📁 目录批量解密模式: {:?}", self.input_path);

        if !self.output_path.exists() {
            fs::create_dir_all(&self.output_path).await?;
            info!("📁 创建输出目录: {:?}", self.output_path);
        }

        if !self.output_path.is_dir() {
            return Err(WeChatError::DecryptionFailed(format!(
                "指定的输出路径不是一个目录: {:?}",
                self.output_path
            ))
            .into());
        }

        let files = collect_files_recursively(self.input_path.to_path_buf()).await?;
        info!("📊 发现 {} 个文件待处理", files.len());

        if self.validate_only {
            info!("✅ 仅验证模式，跳过实际解密");
            if let Some(first_file) = files.first() {
                let validator = KeyValidator::new();
                let version = determine_version(&validator, first_file, &self.key).await?;
                info!("✅ 密钥对第一个文件验证成功！版本: {:?}", version);
            }
            return Ok(());
        }

        info!("🚀 使用 {} 个并发线程处理文件", self.threads);

        let semaphore = Arc::new(Semaphore::new(self.threads));
        let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let failed_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let start_time = std::time::Instant::now();

        let tasks = files.iter().map(|file_path| {
            let sem = semaphore.clone();
            let suc_count = success_count.clone();
            let fail_count = failed_count.clone();
            let key = self.key.clone();
            let file = file_path.clone();
            let in_dir = self.input_path.clone();
            let out_dir = self.output_path.clone();

            async move {
                let _permit = sem.acquire().await.unwrap();
                let relative_path = file.strip_prefix(&in_dir).unwrap();
                let mut output_file = out_dir.join(relative_path);

                if let Some(file_name) = output_file.file_name() {
                    let new_name = format!("decrypted_{}", file_name.to_string_lossy());
                    output_file.set_file_name(new_name);
                }

                if let Some(parent) = output_file.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent).await.ok();
                    }
                }

                match decrypt_file_with_auto_version(&file, &output_file, &key).await {
                    Ok(_) => {
                        suc_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => {
                        fail_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!("⚠️  解密失败: {:?} - {}", file, e);
                    }
                }
            }
        });

        stream::iter(tasks).buffer_unordered(self.threads).collect::<Vec<_>>().await;

        let elapsed = start_time.elapsed();
        info!("🎉 并行批量解密完成！");
        info!("🚀 使用线程数: {}", self.threads);
        info!("📊 总文件数: {}", files.len());
        info!("✅ 成功: {}", success_count.load(std::sync::atomic::Ordering::Relaxed));
        info!("❌ 失败: {}", failed_count.load(std::sync::atomic::Ordering::Relaxed));
        info!("⏱️  总耗时: {:.2} 秒", elapsed.as_secs_f64());
        Ok(())
    }
}

/// 自动检测微信数据库文件的解密版本
///
/// 通过密钥验证器自动检测指定文件应该使用的解密版本。
/// 这是解密过程中的关键步骤，确保使用正确的解密算法。
///
/// # 参数
///
/// * `validator` - 密钥验证器实例
/// * `file_path` - 要检测的数据库文件路径
/// * `key_bytes` - 解密密钥字节数组
///
/// # 返回值
///
/// * `Ok(DecryptVersion)` - 成功检测到的解密版本
/// * `Err(...)` - 版本检测失败
///
/// # 错误
///
/// - 密钥验证失败时返回 `WeChatError::DecryptionFailed`
/// - 无法确定版本时返回相应错误
///
/// # 示例
///
/// ```rust
/// # use anyhow::Result;
/// # async fn example() -> Result<()> {
/// let validator = KeyValidator::new();
/// let version = determine_version(&validator, &file_path, &key_bytes).await?;
/// println!("检测到版本: {:?}", version);
/// # Ok(())
/// # }
/// ```
async fn determine_version(
    validator: &KeyValidator,
    file_path: &Path,
    key_bytes: &[u8],
) -> Result<DecryptVersion> {
    info!("🔍 自动检测 {:?} 的版本...", file_path);
    match validator.validate_key_auto(file_path, key_bytes).await? {
        Some(detected_version) => {
            info!("✅ 检测到版本: {:?}", detected_version);
            Ok(detected_version)
        }
        None => {
            error!("❌ 密钥验证失败，无法确定版本");
            Err(WeChatError::DecryptionFailed("密钥验证失败".to_string()).into())
        }
    }
}

/// 递归收集目录中的所有数据库文件
///
/// 遍历指定目录及其所有子目录，收集所有扩展名为 `.db` 的文件。
/// 使用异步递归实现，通过 `Box::pin` 处理递归 Future 的生命周期问题。
///
/// # 参数
///
/// * `dir` - 要搜索的目录路径
///
/// # 返回值
///
/// 返回一个 `Pin<Box<Future>>` 包装的异步操作，最终产生：
/// * `Ok(Vec<PathBuf>)` - 找到的所有 .db 文件路径列表
/// * `Err(...)` - 目录读取或递归过程中的错误
///
/// # 行为
///
/// - 递归遍历所有子目录
/// - 只收集扩展名为 "db" 的文件
/// - 忽略其他类型的文件和目录
/// - 使用异步 I/O 避免阻塞
///
/// # 错误
///
/// - 目录不存在或无权限访问
/// - 文件系统 I/O 错误
/// - 递归过程中的任何异步操作失败
///
/// # 注意
///
/// 此函数使用 `Box::pin` 是因为 Rust 编译器无法确定递归异步函数的大小，
/// 需要通过堆分配来解决这个问题。
fn collect_files_recursively(dir: PathBuf) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PathBuf>>> + Send>> {
    Box::pin(async move {
        let mut files = Vec::new();
        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_files_recursively(path).await?);
            } else if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("db") {
                files.push(path);
            }
        }
        Ok(files)
    })
}


/// 解密单个数据库文件
///
/// 使用指定的解密版本和密钥对单个微信数据库文件进行解密。
/// 包含性能计时和输出文件验证功能。
///
/// # 参数
///
/// * `input_path` - 输入的加密数据库文件路径
/// * `output_path` - 输出的解密数据库文件路径
/// * `key_bytes` - 解密密钥字节数组
/// * `version` - 要使用的解密版本
///
/// # 返回值
///
/// * `Ok(())` - 解密成功完成
/// * `Err(...)` - 解密过程中发生错误
///
/// # 处理流程
///
/// 1. 根据版本创建相应的解密器
/// 2. 记录开始时间并执行解密操作
/// 3. 计算并记录解密耗时
/// 4. 验证输出文件的有效性
///
/// # 错误
///
/// - 解密器创建失败
/// - 数据库解密过程失败
/// - 输出文件验证失败
///
/// # 性能
///
/// 函数会记录解密操作的耗时，便于性能分析和优化。
async fn decrypt_single_file(
    input_path: &Path,
    output_path: &Path,
    key_bytes: &[u8],
    version: DecryptVersion,
) -> Result<()> {
    info!("📁 输出文件: {:?}", output_path);
    let decryptor = create_decryptor(version);
    info!("🔓 开始解密...");
    let start_time = std::time::Instant::now();

    decryptor
        .decrypt_database_with_progress(input_path, output_path, key_bytes, None)
        .await?;

    let elapsed = start_time.elapsed();
    info!("🎉 解密完成！耗时: {:.2} 秒", elapsed.as_secs_f64());
    verify_output_file(output_path).await?;
    Ok(())
}

/// 自动检测版本并解密文件
///
/// 结合版本自动检测和文件解密功能，适用于批量处理场景。
/// 会先检查文件大小，然后自动检测解密版本，最后执行解密操作。
///
/// # 参数
///
/// * `input_path` - 输入的加密数据库文件路径
/// * `output_path` - 输出的解密数据库文件路径
/// * `key_bytes` - 解密密钥字节数组
///
/// # 返回值
///
/// * `Ok(())` - 解密成功完成
/// * `Err(...)` - 解密过程中发生错误
///
/// # 处理流程
///
/// 1. 检查输入文件大小（小于1024字节的文件会被跳过）
/// 2. 创建密钥验证器并自动检测版本
/// 3. 根据检测到的版本创建解密器
/// 4. 执行数据库解密操作
///
/// # 错误
///
/// - 文件太小（小于1024字节）时返回 `WeChatError::DecryptionFailed`
/// - 版本检测失败
/// - 解密操作失败
///
/// # 文件大小限制
///
/// 为了避免处理无效或损坏的文件，函数会跳过小于1024字节的文件。
/// 这个限制基于正常的微信数据库文件都应该有一定的最小大小。
async fn decrypt_file_with_auto_version(
    input_path: &Path,
    output_path: &Path,
    key_bytes: &[u8],
) -> Result<()> {
    let metadata = fs::metadata(input_path).await?;
    if metadata.len() < 1024 {
        return Err(WeChatError::DecryptionFailed(format!(
            "文件太小，跳过: {:?} ({} 字节)",
            input_path,
            metadata.len()
        ))
        .into());
    }

    let validator = KeyValidator::new();
    let version = determine_version(&validator, input_path, key_bytes).await?;
    let decryptor = create_decryptor(version);

    decryptor
        .decrypt_database_with_progress(input_path, output_path, key_bytes, None)
        .await?;
    Ok(())
}

/// 验证输出文件的有效性
///
/// 检查解密后的输出文件是否为有效的 SQLite 数据库文件。
/// 通过检查文件头部的魔数来验证文件格式的正确性。
///
/// # 参数
///
/// * `output_path` - 要验证的输出文件路径
///
/// # 返回值
///
/// * `Ok(())` - 验证完成（无论文件是否有效都返回 Ok）
/// * `Err(...)` - 文件读取过程中发生 I/O 错误
///
/// # 验证流程
///
/// 1. 检查文件是否存在
/// 2. 获取并记录文件大小
/// 3. 读取文件头部的前16字节
/// 4. 检查是否以 "SQLite format 3" 开头
/// 5. 根据检查结果记录相应的日志信息
///
/// # 行为特点
///
/// - 如果文件不存在，记录错误日志但仍返回 `Ok(())`
/// - 如果文件头部不匹配 SQLite 格式，记录警告但不返回错误
/// - 这种设计允许程序继续运行，即使某些文件验证失败
///
/// # 错误
///
/// 只有在文件 I/O 操作失败时才会返回错误：
/// - 无法获取文件元数据
/// - 无法打开文件
/// - 无法读取文件头部数据
async fn verify_output_file(output_path: &Path) -> Result<()> {
    if !output_path.exists() {
        error!("❌ 输出文件不存在");
        return Ok(());
    }
    let file_size = fs::metadata(output_path).await?.len();
    info!("📊 输出文件大小: {} 字节", file_size);
    let mut file = fs::File::open(output_path).await?;
    let mut header = [0u8; 16];
    use tokio::io::AsyncReadExt;
    file.read_exact(&mut header).await?;
    if header.starts_with(b"SQLite format 3") {
        info!("✅ 输出文件验证成功：有效的SQLite数据库");
    } else {
        warn!("⚠️ 输出文件可能不是有效的SQLite数据库");
    }
    Ok(())
}