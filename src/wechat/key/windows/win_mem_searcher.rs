//! 内存搜索和密钥提取模块
//! 
//! 实现在进程内存中搜索微信密钥的核心算法

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use crate::errors::{Result, WeChatError};
use crate::utils::windows::handle::Handle;
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            Memory::{
                VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE,
                PAGE_READWRITE,
            },
            Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
};

/// 内存搜索配置
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// 最大工作线程数
    pub max_workers: usize,
    /// 内存通道缓冲区大小
    pub memory_channel_buffer: usize,
    /// 最小内存区域大小（字节）
    pub min_region_size: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_workers: std::cmp::min(num_cpus::get(), 16),
            memory_channel_buffer: 100,
            min_region_size: 1024 * 1024, // 1MB
        }
    }
}

/// 搜索结果
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// 找到的密钥
    pub key: String,
    /// 密钥地址
    pub address: usize,
    /// 验证顺序
    pub order: usize,
}

/// 内存搜索器
pub struct MemorySearcher {
    /// 搜索模式
    pattern: Vec<u8>,
    /// 密钥限制数量
    key_limit: usize,
    /// 搜索配置
    config: SearchConfig,
    /// 目标密钥（用于验证）
    target_key: String,
}

impl MemorySearcher {
    /// 创建新的内存搜索器
    pub fn new(pattern: Vec<u8>, key_limit: usize) -> Self {
        Self {
            pattern,
            key_limit,
            config: SearchConfig::default(),
            target_key: "4ced5efc9ecc4b818d16ee782a6d4d2eda3f25a030b143a1aff93a0d322c920b".to_string(),
        }
    }

    /// 使用自定义配置创建内存搜索器
    pub fn with_config(pattern: Vec<u8>, key_limit: usize, config: SearchConfig) -> Self {
        Self {
            pattern,
            key_limit,
            config,
            target_key: "4ced5efc9ecc4b818d16ee782a6d4d2eda3f25a030b143a1aff93a0d322c920b".to_string(),
        }
    }

    /// 在指定进程中搜索密钥
    pub fn search_keys(&self, pid: u32) -> Result<Vec<SearchResult>> {
        // 创建跨线程通道
        let (mem_sender, mem_receiver) = crossbeam_channel::unbounded::<Vec<u8>>();
        let (result_sender, result_receiver) = crossbeam_channel::unbounded::<SearchResult>();

        // 创建全局停止信号
        let stop_signal = Arc::new(AtomicBool::new(false));
        
        // 创建计数器
        let success_counter = Arc::new(AtomicUsize::new(0));
        let failure_counter = Arc::new(AtomicUsize::new(0));

        // 启动 Worker 线程
        let worker_count = self.config.max_workers;
        println!("[MemorySearcher] 启动 {} workers...", worker_count);
        let mut worker_handles = Vec::new();
        
        for i in 0..worker_count {
            let receiver = mem_receiver.clone();
            let sender = result_sender.clone();
            let stop = Arc::clone(&stop_signal);
            let success_clone = Arc::clone(&success_counter);
            let failure_clone = Arc::clone(&failure_counter);
            let pattern = self.pattern.clone();
            let target_key = self.target_key.clone();
            let key_limit = self.key_limit;

            worker_handles.push(
                thread::Builder::new()
                    .name(format!("mem-worker-{}", i))
                    .spawn(move || {
                        let _ = Self::worker_impl(
                            pid,
                            receiver,
                            sender,
                            stop,
                            success_clone,
                            failure_clone,
                            pattern,
                            target_key,
                            key_limit,
                        );
                    })
                    .unwrap(),
            );
        }

        // 当 result_sender 的最后一个克隆离开作用域时，channel 会关闭
        drop(result_sender);

        // 启动 Producer 线程
        println!("[MemorySearcher] Starting producer...");
        let producer_stop_signal = Arc::clone(&stop_signal);
        let producer_handle = thread::Builder::new()
            .name("mem-producer".to_string())
            .spawn(move || {
                Self::find_memory_impl(pid, mem_sender, producer_stop_signal);
            })
            .unwrap();

        // 等待生产者完成
        producer_handle.join().expect("Producer thread panicked");
        println!("[MemorySearcher] Producer finished.");

        // 等待所有 worker 完成
        for handle in worker_handles {
            handle.join().expect("Worker thread panicked");
        }
        println!("[MemorySearcher] All workers finished.");

        // 收集结果
        let mut results = Vec::new();
        while let Ok(result) = result_receiver.try_recv() {
            results.push(result);
        }

        // 按验证顺序排序
        results.sort_by_key(|r| r.order);

        // 根据key_limit限制返回结果
        if results.len() > self.key_limit {
            results.truncate(self.key_limit);
        }

        Ok(results)
    }

    /// Worker 线程实现
    fn worker_impl(
        pid: u32,
        receiver: crossbeam_channel::Receiver<Vec<u8>>,
        sender: crossbeam_channel::Sender<SearchResult>,
        stop_signal: Arc<AtomicBool>,
        success_counter: Arc<AtomicUsize>,
        failure_counter: Arc<AtomicUsize>,
        pattern: Vec<u8>,
        target_key: String,
        key_limit: usize,
    ) -> anyhow::Result<()> {
        let process_handle = match Handle::new(unsafe {
            match OpenProcess(PROCESS_VM_READ, false, pid) {
                Ok(h) => h,
                Err(e) => return Err(anyhow::anyhow!("[Worker] Failed to open process: {}", e)),
            }
        }) {
            Ok(h) => h,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "[Worker] Failed to create handle wrapper: {}",
                    e
                ))
            }
        };

        let ptr_size = std::mem::size_of::<usize>();

        while let Ok(memory) = receiver.recv() {
            // 使用SeqCst内存顺序以确保更快的信号传播
            if stop_signal.load(Ordering::SeqCst) {
                // 如果已经收到停止信号，清空接收队列中的所有剩余内存块
                while receiver.try_recv().is_ok() {}
                break;
            }

            for (i, window) in memory.windows(pattern.len()).enumerate().rev() {
                // 每处理100个窗口检查一次停止信号，避免不必要的处理
                if i % 100 == 0 && stop_signal.load(Ordering::SeqCst) {
                    return Ok(());
                }

                if window == pattern {
                    let ptr_start_index = i.saturating_sub(ptr_size);
                    if ptr_start_index < i {
                        let ptr_bytes = &memory[ptr_start_index..i];
                        let ptr_value = usize::from_le_bytes(ptr_bytes.try_into().unwrap());
                        if ptr_value > 0x10000 && ptr_value < 0x7FFFFFFFFFFF {
                            // 在验证前再次检查停止信号
                            if stop_signal.load(Ordering::SeqCst) {
                                return Ok(());
                            }

                            // 调用验证函数
                            match Self::validate_key_impl(
                                *process_handle,
                                ptr_value,
                                Arc::clone(&stop_signal),
                                &target_key,
                            ) {
                                Some(key) => {
                                    // 成功路径：在worker层面处理统计
                                    let validation_order = success_counter.fetch_add(1, Ordering::SeqCst);
                                    
                                    // 检查是否超过key_limit
                                    if validation_order >= key_limit {
                                        return Ok(());
                                    }
                                    
                                    println!(
                                        "\n🎉 [Validator] SUCCESS! No.{} success. Failures so far: {}. Addr: {:#X}\n",
                                        validation_order + 1,
                                        failure_counter.load(Ordering::Relaxed),
                                        ptr_value
                                    );
                                    
                                    let result = SearchResult {
                                        key,
                                        address: ptr_value,
                                        order: validation_order,
                                    };
                                    
                                    let _ = sender.try_send(result);
                                    
                                    // 如果达到key_limit，设置停止信号
                                    if validation_order + 1 >= key_limit {
                                        println!("[Worker] Key limit reached. Raising stop signal.");
                                        stop_signal.store(true, Ordering::SeqCst);
                                        // 清空接收队列中的所有剩余内存块
                                        while receiver.try_recv().is_ok() {}
                                        return Ok(());
                                    }
                                }
                                None => {
                                    // 失败路径：在worker层面处理统计
                                    let total_failures = failure_counter.fetch_add(1, Ordering::Relaxed);
                                    
                                    // 为了避免日志刷屏，我们可以选择性地打印，比如每10次失败打印一次
                                    if (total_failures + 1) % 10 == 0 {
                                        println!(
                                            "[Validator] Mismatch... Total failures reached: {}",
                                            total_failures + 1
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Producer 线程实现 - 扫描进程内存
    fn find_memory_impl(
        pid: u32,
        sender: crossbeam_channel::Sender<Vec<u8>>,
        stop_signal: Arc<AtomicBool>,
    ) {
        println!("[Producer] Started.");
        let handle =
            match unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid) } {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[Producer] Error: Failed to open process handle: {:?}", e);
                    return;
                }
            };
        // 使用 Handle 结构体代替 HandleGuard
        let _handle = match Handle::new(handle) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[Producer] Error: Failed to create handle wrapper: {:?}", e);
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

        println!(
            "[Producer] Starting memory scan from {:#X} to {:#X}",
            min_addr, max_addr
        );
        while current_addr < max_addr {
            // 关键优化：检查停止信号，使用SeqCst内存顺序以确保更快的信号传播
            if stop_signal.load(Ordering::SeqCst) {
                println!("[Producer] Stop signal received. Halting memory scan.");
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
                println!("[Producer] VirtualQueryEx finished or failed. Exiting scan loop.");
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
                    println!("[Producer] Stop signal received before memory read. Halting scan.");
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
                        println!(
                            "[Producer] Stop signal received after memory read. Halting scan."
                        );
                        break;
                    }

                    buffer.truncate(bytes_read);
                    if sender.send(buffer).is_err() {
                        // 如果发送失败，说明 workers 已经全部退出，也意味着可以停止了
                        println!("[Producer] Workers' channel closed. Stopping early.");
                        break;
                    }
                }
            }

            let next_addr = (mem_info.BaseAddress as usize).saturating_add(region_size);
            if next_addr <= current_addr {
                eprintln!("[Producer] Error: Address not advancing! current: {:#X}, next: {:#X}. Breaking.", current_addr, next_addr);
                break;
            }
            current_addr = next_addr;
        }
        println!("[Producer] Memory scan finished. Closing sender channel.");
    }

    /// 验证密钥实现
    fn validate_key_impl(
        handle: HANDLE,
        addr: usize,
        stop_signal: Arc<AtomicBool>,
        target_key: &str,
    ) -> Option<String> {
        // 在验证前先检查停止信号，如果已经设置了停止信号，则不再验证
        if stop_signal.load(Ordering::SeqCst) {
            return None;
        }

        let mut key_data = vec![0u8; 32];
        let mut bytes_read = 0;
        let result = unsafe {
            ReadProcessMemory(
                handle,
                addr as *const _,
                key_data.as_mut_ptr() as *mut _,
                32,
                Some(&mut bytes_read),
            )
        };

        if result.is_ok() && bytes_read == 32 {
            let found_key_str = hex::encode(&key_data);
            if found_key_str == target_key {
                // 成功路径：直接返回找到的key，不进行统计
                return Some(found_key_str);
            }
        }
        
        // 失败路径：直接返回None，不进行统计
        None
    }
}