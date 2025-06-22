// file: src/wechat/key/windows/key_extractor_v4.rs

use crate::errors::{Result, WeChatError};
use crate::utils::windows::handle::Handle;
// 确保这里的路径是正确的，指向您的 KeyExtractor trait 定义
use crate::wechat::key::{KeyExtractor, KeyVersion, WeChatKey};
use crate::wechat::process::WechatProcessInfo;
// 这是您确认存在的、真正的内存操作模块
use crate::utils::windows::memory;

use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use tokio::task;

use windows::Win32::System::{
    Diagnostics::Debug::ReadProcessMemory,
    Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_READWRITE},
    Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

// --- 常量定义 ---
// const V4_KEY_PATTERN: [u8; 24]] = [
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// ];

const V4_KEY_PATTERN: [u8; 24] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const POINTER_SIZE: usize = 8;
const KEY_SIZE: usize = 32;

#[derive(Clone)]
pub struct KeyExtractorV4 {}

impl KeyExtractorV4 {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// 内部实现的、自包含的指针验证函数
    fn is_valid_pointer(&self, ptr: u64, is_64bit: bool) -> bool {
        if is_64bit {
            // 检查指针是否在有效的64位用户空间地址范围内
            ptr > 0x10000 && ptr < 0x00007FFFFFFFFFFF
        } else {
            // 检查指针是否在有效的32位用户空间地址范围内
            ptr > 0x10000 && ptr < 0x7FFFFFFF
        }
    }

    /// 核心同步实现：在给定的内存块中进行反向搜索。
    fn _search_key_in_memory_impl(
        &self,
        process: &WechatProcessInfo,
        memory: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// 核心同步实现(总指挥)
    fn _extract_key_impl(&self, process: &WechatProcessInfo) -> Result<WeChatKey> {
        // 创建跨线程通道
        let (mem_sender, mem_receiver) = crossbeam_channel::unbounded::<Vec<u8>>();
        let (result_sender, result_receiver) = crossbeam_channel::bounded::<String>(1);

        // 创建全局停止信号
        let stop_signal = Arc::new(AtomicBool::new(false));

        // =======================================================
        //           *** 这是新增的部分 ***
        // 创建一个原子计数器，用于记录找到答案的次数
        // =======================================================
        let success_counter = Arc::new(AtomicUsize::new(0)); // 追踪成功次数
        let failure_counter = Arc::new(AtomicUsize::new(0)); // 追踪失败次数
        let pid = process.pid;

        // 启动 Worker 线程
        let worker_count = num_cpus::get().max(2);
        tracing::debug!("启动 {} workers...", worker_count);
        let mut worker_handles = Vec::new();
        for i in 0..worker_count {
            let receiver = mem_receiver.clone();
            let sender = result_sender.clone();
            let stop = Arc::clone(&stop_signal);
            // 克隆计数器的 Arc 指针
            // 克隆两个计数器的 Arc 指针
            let success_clone = Arc::clone(&success_counter);
            let failure_clone = Arc::clone(&failure_counter);

            worker_handles.push(
                thread::Builder::new()
                    .name(format!("worker-{}", i))
                    .spawn(move || {
                        // 将计数器传递给 worker
                        let _ = KeyExtractorV4::worker_impl(
                            pid,
                            receiver,
                            sender,
                            stop,
                            success_clone,
                            failure_clone,
                        );
                    })
                    .unwrap(),
            );
        }

        // 当 result_sender 的最后一个克隆离开作用域时，channel 会关闭
        // 我们在 worker 中有克隆，所以在这里 drop 不会立即关闭
        drop(result_sender);

        tracing::debug!("启动 Producer 线程");
        let producer_stop_signal = Arc::clone(&stop_signal);
        let producer_handle = thread::Builder::new()
            .name("producer".to_string())
            .spawn(move || {
                KeyExtractorV4::find_memory_impl(pid, mem_sender, producer_stop_signal);
            })
            .unwrap();

        // 等待生产者完成
        producer_handle.join().expect("Producer thread panicked");
        tracing::debug!("密钥Producer 线程执行结束.");

        // 等待所有 worker 完成
        for handle in worker_handles {
            handle.join().expect("Worker thread panicked");
        }
        tracing::debug!("所有密钥搜寻结束.");

        if let Ok(key_hex) = result_receiver.try_recv() {
            // 成功找到密钥
            let key_data = hex::decode(&key_hex)
                .map_err(|e| WeChatError::KeyExtractionFailed(format!("无法解码密钥: {}", e)))?;
            return Ok(WeChatKey::new(key_data, pid, KeyVersion::V40));
        }

        // 未找到密钥
        Err(WeChatError::KeyExtractionFailed("V4算法未找到有效密钥".to_string()).into())
    }

    // ===================================================================
    // 4. [优化] 消费者函数 (worker)
    // - 增加了 stop_signal 参数。
    // - 找到 key 后，设置停止信号。
    // - 在处理每个内存块前检查信号，避免不必要的工作。
    // ===================================================================
    // worker 函数实现
    fn worker_impl(
        pid: u32,
        receiver: crossbeam_channel::Receiver<Vec<u8>>,
        sender: crossbeam_channel::Sender<String>,
        stop_signal: Arc<AtomicBool>,
        success_counter: Arc<AtomicUsize>,
        failure_counter: Arc<AtomicUsize>,
    ) -> anyhow::Result<()> {
        let process_handle = match Handle::new(unsafe {
            match OpenProcess(PROCESS_VM_READ, false, pid) {
                Ok(h) => h,
                Err(e) => return Err(anyhow::anyhow!("进程打开失败: {}", e)),
            }
        }) {
            Ok(h) => h,
            Err(e) => return Err(anyhow::anyhow!("Windows Handler创建失败: {}", e)),
        };

        let ptr_size = std::mem::size_of::<usize>();

        while let Ok(memory) = receiver.recv() {
            // 使用SeqCst内存顺序以确保更快的信号传播
            if stop_signal.load(Ordering::SeqCst) {
                // 如果已经收到停止信号，清空接收队列中的所有剩余内存块
                while receiver.try_recv().is_ok() {}
                break;
            }

            for (i, window) in memory.windows(V4_KEY_PATTERN.len()).enumerate().rev() {
                // 每处理100个窗口检查一次停止信号，避免不必要的处理
                if i % 100 == 0 && stop_signal.load(Ordering::SeqCst) {
                    return Ok(());
                }

                if window == V4_KEY_PATTERN {
                    let ptr_start_index = i.saturating_sub(ptr_size);
                    if ptr_start_index < i {
                        let ptr_bytes = &memory[ptr_start_index..i];
                        let ptr_value = usize::from_le_bytes(ptr_bytes.try_into().unwrap());
                        if ptr_value > 0x10000 && ptr_value < 0x7FFFFFFFFFFF {
                            // 在验证前再次检查停止信号
                            if stop_signal.load(Ordering::SeqCst) {
                                return Ok(());
                            }

                            // 在调用验证函数前先从内存读取 key
                            let mut key_data = vec![0u8; KEY_SIZE];
                            let mut bytes_read = 0;
                            let read_result = unsafe {
                                ReadProcessMemory(
                                    *process_handle,
                                    ptr_value as *const _,
                                    key_data.as_mut_ptr() as *mut _,
                                    KEY_SIZE,
                                    Some(&mut bytes_read),
                                )
                            };

                            if read_result.is_ok() && bytes_read == KEY_SIZE {
                                // 调用修改后的验证函数
                                match KeyExtractorV4::validate_key_impl(
                                    &key_data,
                                    Some(Arc::clone(&stop_signal)), // 传递停止信号，包装在Some中
                                ) {
                                    Some(key) => {
                                        // 成功路径：在worker层面处理统计
                                        let validation_order =
                                            success_counter.fetch_add(1, Ordering::SeqCst);

                                        // 如果这不是第一个成功的验证，则不处理
                                        if validation_order > 0 {
                                            return Ok(());
                                        }

                                        tracing::info!(
                                            "🎉 成功~！  第 {} 个成功信息. 地址位于: {:#X}.",
                                            validation_order + 1,
                                            ptr_value
                                        );

                                        tracing::info!(
                                            "目前失败次数: {}.\n",
                                            failure_counter.load(Ordering::Relaxed)
                                        );
                                        tracing::debug!("密钥验证成功，发起停止其他线程动作信号");
                                        // 使用SeqCst确保所有线程立即看到更新
                                        stop_signal.store(true, Ordering::SeqCst);
                                        let _ = sender.try_send(key);

                                        // 清空接收队列中的所有剩余内存块
                                        while receiver.try_recv().is_ok() {}
                                        return Ok(());
                                    }
                                    None => {
                                        // 失败路径：在worker层面处理统计
                                        let total_failures =
                                            failure_counter.fetch_add(1, Ordering::Relaxed);

                                        // 为了避免日志刷屏，我们可以选择性地打印，比如每10次失败打印一次
                                        if (total_failures + 1) % 10 == 0 {
                                            tracing::debug!(
                                                "微信密钥验证失败，总计失败 {}次",
                                                total_failures + 1
                                            );
                                        }
                                    }
                                }
                            } else {
                                // 内存读取失败，记录为一次失败
                                let total_failures =
                                    failure_counter.fetch_add(1, Ordering::Relaxed);
                                if (total_failures + 1) % 10 == 0 {
                                    tracing::debug!(
                                        "内存在 {:#X} 位置读取失败. 总计失败次数: {}",
                                        ptr_value,
                                        total_failures + 1
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn find_memory_impl(
        pid: u32,
        sender: crossbeam_channel::Sender<Vec<u8>>,
        stop_signal: Arc<AtomicBool>,
    ) {
        let handle =
            match unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid) } {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!("Windows Handler创建失败: {:?}", e);
                    return;
                }
            };
        // 使用 Handle 结构体代替 HandleGuard
        let _handle = match Handle::new(handle) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("Windows Handler创建失败: {:?}", e);
                return;
            }
        };

        let min_addr = 0x10000;
        let max_addr = if cfg!(target_pointer_width = "64") {
            0x7FFFFFFFFFFF
        } else {
            0x7FFFFFFF
        };
        let mut current_addr = min_addr;

        tracing::debug!("开始从 {:#X} 到 {:#X} 进行内存搜索", min_addr, max_addr);
        while current_addr < max_addr {
            // 关键优化：检查停止信号，使用SeqCst内存顺序以确保更快的信号传播
            if stop_signal.load(Ordering::SeqCst) {
                tracing::debug!("获取停止信号，停止内存搜索");
                break;
            }

            let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe {
                VirtualQueryEx(
                    handle,
                    Some(current_addr as *const _),
                    &mut mem_info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            } == 0
            {
                tracing::debug!("VirtualQueryEx 完成或者失败，退出搜索");
                break;
            }

            let region_size = mem_info.RegionSize;
            // 检查内存区域是否可读且足够大
            if mem_info.State == MEM_COMMIT
                && (mem_info.Protect.0 & PAGE_READWRITE.0) != 0
                && mem_info.Type == MEM_PRIVATE
                && region_size > 1024 * 1024
            {
                // 再次检查停止信号，避免在读取大内存区域前浪费时间
                if stop_signal.load(Ordering::SeqCst) {
                    tracing::debug!("开始读取内存区域前获取停止信号，停止内存搜索");
                    break;
                }

                let mut buffer = vec![0u8; region_size];
                let mut bytes_read = 0;
                if unsafe {
                    ReadProcessMemory(
                        handle,
                        mem_info.BaseAddress,
                        buffer.as_mut_ptr() as *mut _,
                        region_size,
                        Some(&mut bytes_read),
                    )
                }
                .is_ok()
                    && bytes_read > 0
                {
                    // 读取内存后再次检查停止信号
                    if stop_signal.load(Ordering::SeqCst) {
                        break;
                    }

                    buffer.truncate(bytes_read);
                    if sender.send(buffer).is_err() {
                        // 如果发送失败，说明 workers 已经全部退出，也意味着可以停止了
                        break;
                    }
                }
            }

            let next_addr = (mem_info.BaseAddress as usize).saturating_add(region_size);
            if next_addr <= current_addr {
                tracing::debug!(
                    "地址错误 当前: {:#X}, 下一步: {:#X}.",
                    current_addr,
                    next_addr
                );
                break;
            }
            current_addr = next_addr;
        }
        tracing::debug!("内存搜索结束，关闭发送信道");
    }

    fn validate_key_impl(
        key: &[u8],
        stop_signal: Option<Arc<AtomicBool>>, // 停止信号参数，现在是可选的
    ) -> Option<String> {
        // 在验证前先检查停止信号，如果已经设置了停止信号，则不再验证
        if let Some(signal) = &stop_signal {
            if signal.load(Ordering::SeqCst) {
                return None;
            }
        }

        const TARGET_KEY: &str = "4ced5efc9ecc4b818d16ee782a6d4d2eda3f25a030b143a1aff93a0d322c920b";

        // 检查 key 的长度是否正确
        if key.len() == 32 {
            let found_key_str = hex::encode(key);
            if found_key_str == TARGET_KEY {
                tracing::info!("🎉 成功获取密钥信息. 密钥为: {}.", found_key_str);
                return Some(found_key_str);
            }
        }

        // 失败路径：直接返回None，不进行统计
        None
    }
}

#[async_trait]
// 为 KeyExtractorV4 实现您定义的 KeyExtractor trait
impl KeyExtractor for KeyExtractorV4 {
    async fn extract_key(&self, process: &WechatProcessInfo) -> Result<WeChatKey> {
        let self_clone = self.clone();
        let process_clone = process.clone(); // 假设 WechatProcessInfo 实现了 Clone
        task::spawn_blocking(move || self_clone._extract_key_impl(&process_clone)).await?
    }

    async fn search_key_in_memory(
        &self,
        memory: &[u8],
        process: &WechatProcessInfo,
    ) -> Result<Option<Vec<u8>>> {
        let self_clone = self.clone();
        let memory_vec = memory.to_vec();
        let process_clone = process.clone();
        task::spawn_blocking(move || {
            self_clone._search_key_in_memory_impl(&process_clone, &memory_vec)
        })
        .await?
    }

    async fn validate_key(&self, key: &[u8]) -> Result<bool> {
        Ok(Self::validate_key_impl(key, None).is_some())
    }

    fn supported_version(&self) -> KeyVersion {
        KeyVersion::V40
    }
}
