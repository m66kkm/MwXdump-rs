// file: src/wechat/key/windows/key_extractor_v4.rs

use crate::errors::{Result, WeChatError};
use crate::utils::windows::handle::Handle;
// 确保这里的路径是正确的，指向您的 KeyExtractor trait 定义
use crate::wechat::key::{KeyExtractor, KeyVersion, WeChatKey};
use crate::wechat::process::WechatProcessInfo;
// 这是您确认存在的、真正的内存操作模块
use crate::utils::windows::{handle, memory};

use async_trait::async_trait;
use byteorder::{ByteOrder, LittleEndian};
use tokio::task;
use tracing::{debug, info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize; 
use std::thread;

use windows::{
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
            },
            Memory::{
                VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            },
            Threading::{
                OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
        },
    },
};



// --- 常量定义 ---
const V4_KEY_PATTERN: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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


        // if memory.len() < V4_KEY_PATTERN.len() {
        //     return Ok(None);
        // }

        // // 使用 .rev() 实现从后向前的迭代搜索，对齐Go的LastIndex逻辑
        // for pos in (0..=memory.len() - V4_KEY_PATTERN.len()).rev() {
        //     if &memory[pos..pos + V4_KEY_PATTERN.len()] == V4_KEY_PATTERN {
        //         if pos < POINTER_SIZE { continue; }

        //         let pointer_bytes_slice = &memory[(pos - POINTER_SIZE)..pos];
        //         let key_address = LittleEndian::read_u64(pointer_bytes_slice);

        //         // 调用内部实现的指针验证
        //         if !self.is_valid_pointer(key_address, process.is_64_bit) {
        //             continue;
        //         }

        //         if let Ok(key_candidate) = memory::read_process_memory(process.pid, key_address as usize, KEY_SIZE) {
        //             if self._validate_key_impl(&key_candidate) {
        //                 debug!("在内存块偏移 {} 处找到模式，其指针 {:#x} 指向有效密钥", pos, key_address);
        //                 return Ok(Some(key_candidate)); // 找到第一个就返回
        //             }
        //         }
        //     }
        // }
        
        Ok(None)
    }

    /// 核心同步实现(验证逻辑)
    fn _validate_key_impl(&self, key: &[u8]) -> bool {
        key.len() == KEY_SIZE && !key.iter().all(|&b| b == 0)
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
        // 启动 Worker 线程
        let worker_count = num_cpus::get().max(2);
        tracing::debug!("[KeyExtractorV4] 启动 {} workers...", worker_count);
        let mut worker_handles = Vec::new();
        for i in 0..worker_count {
            let receiver = mem_receiver.clone();
            let sender = result_sender.clone();
            let stop = Arc::clone(&stop_signal);
            // 克隆计数器的 Arc 指针
            // 克隆两个计数器的 Arc 指针
            let success_clone = Arc::clone(&success_counter);
            let failure_clone = Arc::clone(&failure_counter);

            worker_handles.push(thread::Builder::new().name(format!("worker-{}", i)).spawn(move || {
                // 将计数器传递给 worker
                let _ = worker(pid, receiver, sender, stop, success_clone, failure_clone);
            }).unwrap());
        }

        // 当 result_sender 的最后一个克隆离开作用域时，channel 会关闭
        // 我们在 worker 中有克隆，所以在这里 drop 不会立即关闭
        drop(result_sender);

        // 启动 Producer 线程
        println!("[Main] Starting producer...");
        let producer_stop_signal = Arc::clone(&stop_signal);
        let producer_handle = thread::Builder::new().name("producer".to_string()).spawn(move || {
            find_memory(pid, mem_sender, producer_stop_signal);
        }).unwrap();

        // 等待生产者完成
        producer_handle.join().expect("Producer thread panicked");
        println!("[Main] Producer finished.");

        // 等待所有 worker 完成
        for handle in worker_handles {
            handle.join().expect("Worker thread panicked");
        }
        println!("[Main] All workers finished.");

        // 获取结果
        println!("[Main] Retrieving result...");
        result_receiver.try_recv().map_err(|_| Error::NoValidKey.into())

        Err(WeChatError::KeyExtractionFailed("V4算法未找到有效密钥".to_string()).into())
    }

    // ===================================================================
    // 4. [优化] 消费者函数 (worker)
    // - 增加了 stop_signal 参数。
    // - 找到 key 后，设置停止信号。
    // - 在处理每个内存块前检查信号，避免不必要的工作。
    // ===================================================================
    // worker 函数
    fn worker(
        pid: u32,
        receiver: crossbeam_channel::Receiver<Vec<u8>>,
        sender: crossbeam_channel::Sender<String>,
        stop_signal: Arc<AtomicBool>,
        success_counter: Arc<AtomicUsize>,
        failure_counter: Arc<AtomicUsize>,
    ) -> anyhow::Result<()> {
        let process_handle = Handle::new(unsafe { OpenProcess(PROCESS_VM_READ, false, pid)? })?;
        
        let key_pattern = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let ptr_size = std::mem::size_of::<usize>();

        while let Ok(memory) = receiver.recv() {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            for (i, window) in memory.windows(key_pattern.len()).enumerate().rev() {
                if window == key_pattern {
                    let ptr_start_index = i.saturating_sub(ptr_size);
                    if ptr_start_index < i {
                        let ptr_bytes = &memory[ptr_start_index..i];
                        let ptr_value = usize::from_le_bytes(ptr_bytes.try_into().unwrap());
                        if ptr_value > 0x10000 && ptr_value < 0x7FFFFFFFFFFF {
                            // 传递两个计数器
                            if let Some(key) = validate_key(
                                handle,
                                ptr_value,
                                Arc::clone(&success_counter),
                                Arc::clone(&failure_counter),
                            ) {
                                println!("[Worker] Correct key validated! Raising stop signal.");
                                stop_signal.store(true, Ordering::Relaxed);
                                let _ = sender.try_send(key);
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
        
    fn find_memory(pid: u32, sender: crossbeam_channel::Sender<Vec<u8>>, stop_signal: Arc<AtomicBool>) {
        println!("[Producer] Started.");
        let handle = match unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[Producer] Error: Failed to open process handle: {:?}", e);
                return;
            }
        };
        let _handle_guard = HandleGuard(handle);

        let min_addr = 0x10000;
        let max_addr = if cfg!(target_pointer_width = "64") { 0x7FFFFFFFFFFF } else { 0x7FFFFFFF };
        let mut current_addr = min_addr;

        println!("[Producer] Starting memory scan from {:#X} to {:#X}", min_addr, max_addr);
        while current_addr < max_addr {
            // 关键优化：检查停止信号
            if stop_signal.load(Ordering::Relaxed) {
                println!("[Producer] Stop signal received. Halting memory scan.");
                break;
            }

            let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe { VirtualQueryEx(handle, Some(current_addr as *const _), &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 {
                println!("[Producer] VirtualQueryEx finished or failed. Exiting scan loop.");
                break;
            }

            let region_size = mem_info.RegionSize;
            if mem_info.State == MEM_COMMIT && (mem_info.Protect.0 & PAGE_READWRITE.0) != 0 && mem_info.Type == MEM_PRIVATE && region_size > 1024 * 1024 {
                let mut buffer = vec![0u8; region_size];
                let mut bytes_read = 0;
                if unsafe { ReadProcessMemory(handle, mem_info.BaseAddress, buffer.as_mut_ptr() as *mut _, region_size, Some(&mut bytes_read)) }.is_ok() && bytes_read > 0 {
                    // println!("[Producer] Found candidate region at {:#X}, size: {}. Sending to workers.", mem_info.BaseAddress as usize, bytes_read);
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


    fn validate_key(
        handle: HANDLE,
        addr: usize,
        success_counter: Arc<AtomicUsize>, // <--- 成功计数器
        failure_counter: Arc<AtomicUsize>, // <--- 失败计数器
    ) -> Option<String> {
        const TARGET_KEY: &str = "4ced5efc9ecc4b818d16ee782a6d4d2eda3f25a030b143a1aff93a0d322c920b";

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
            if found_key_str == TARGET_KEY {
                // 成功路径：增加成功计数器
                let validation_order = success_counter.fetch_add(1, Ordering::SeqCst);
                println!(
                    "\n🎉 [Validator] SUCCESS! No.{} success. Failures so far: {}. Addr: {:#X}\n",
                    validation_order + 1,
                    failure_counter.load(Ordering::Relaxed), // 读取失败次数
                    addr
                );
                return Some(found_key_str);
            } else {
                // =======================================================
                //           *** 这是新增的失败路径 ***
                // =======================================================
                // 失败路径：增加失败计数器
                
                let total_failures = failure_counter.fetch_add(1, Ordering::Relaxed);
                
                // 为了避免日志刷屏，我们可以选择性地打印，比如每1000次失败打印一次
                if (total_failures + 1) % 10 == 0 {
                    println!(
                        "[Validator] Mismatch... Total failures reached: {}",
                        total_failures + 1
                    );
                }
                return None;
            }
        } else {
            // 读取内存失败也算作一次失败
            failure_counter.fetch_add(1, Ordering::Relaxed);
            return None;
        }
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

    async fn search_key_in_memory(&self, memory: &[u8], process: &WechatProcessInfo) -> Result<Option<Vec<u8>>> {
        let self_clone = self.clone();
        let memory_vec = memory.to_vec();
        let process_clone = process.clone();
        task::spawn_blocking(move || self_clone._search_key_in_memory_impl(&process_clone, &memory_vec)).await?
    }
    
    async fn validate_key(&self, key: &[u8]) -> Result<bool> {
        Ok(self._validate_key_impl(key))
    }
    
    fn supported_version(&self) -> KeyVersion {
        KeyVersion::V40
    }
}