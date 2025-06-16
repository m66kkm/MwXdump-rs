//! 版本命令实现

use crate::cli::context::ExecutionContext;
use crate::errors::Result;

// ... 省略 use crate::...

// ===================================================================
// 主执行函数 (execute)
// 基本不变，只是调用了新的 extract
// ===================================================================
pub async fn execute(context: &ExecutionContext) -> Result<()> {
    let fake_process = model::Process {
        pid: 19472, // 替换为你要调试的进程ID
        status: model::Status::Online,
    };

    println!("Starting key extraction for PID: {}", fake_process.pid);
    match extract(&fake_process) {
        Ok(key) => println!("\n🎉 Successfully found key: {}", key),
        Err(e) => println!("\n❌ Extraction failed: {:?}", e),
    }

    Ok(())
}

// ===================================================================
// 核心模块依赖
// ===================================================================
use anyhow::anyhow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use thiserror::Error;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use std::sync::atomic::AtomicUsize; 

// ===================================================================
// 数据模型 (model) - 不变
// ===================================================================
mod model {
    // ... (代码不变)
    #[derive(PartialEq)]
    pub enum Status {
        Online,
        Offline,
    }
    pub struct Process {
        pub pid: u32,
        pub status: Status,
    }
}

// ===================================================================
// 错误定义 (Error) - 不变
// ===================================================================
#[derive(Error, Debug)]
pub enum Error {
    // ... (代码不变)
    #[error("WeChat is offline")]
    WeChatOffline,
    #[error("Failed to open process")]
    OpenProcessFailed,
    #[error("No valid key was found in the process memory")]
    NoValidKey,
}

// ===================================================================
// 1. [重构] HandleGuard 提取为公共工具
// 避免在多个函数中重复定义，符合 DRY 原则。
// ===================================================================
struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

// ===================================================================
// 2. [优化] 主协调函数 (extract)
// - 移除了多余的 handle 创建。
// - 增加了 Arc<AtomicBool> 作为全局停止信号。
// - 将停止信号分发给所有线程。
// - 精简了日志。
// ===================================================================
fn extract(proc: &model::Process) -> Result<String> {
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

    let mut worker_handles = Vec::new();
    let pid = proc.pid;

    // 启动 Worker 线程
    let worker_count = num_cpus::get().max(2);
    println!("[Main] Starting {} workers...", worker_count);
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
}


// ===================================================================
// 3. [优化] 生产者函数 (find_memory)
// - 增加了 stop_signal 参数。
// - 在循环开始时检查信号，以便能被提前中断。
// ===================================================================
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
    let handle = unsafe {
        OpenProcess(PROCESS_VM_READ, false, pid)
            .map_err(|e| anyhow!("[Worker] Failed to open process: {}", e))?
    };
    let _handle_guard = HandleGuard(handle);

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
// fn validate_key(handle: HANDLE, addr: usize, counter: Arc<AtomicUsize>) -> Option<String> { 
//     // 我们的“标准答案”
//     const TARGET_KEY: &str = "4ced5efc9ecc4b818d16ee782a6d4d2eda3f25a030b143a1aff93a0d322c920b";

//     let mut key_data = vec![0u8; 32];
//     let mut bytes_read = 0;
//     let result = unsafe {
//         ReadProcessMemory(
//             handle,
//             addr as *const _,
//             key_data.as_mut_ptr() as *mut _,
//             32,
//             Some(&mut bytes_read),
//         )
//     };

//     if result.is_ok() && bytes_read == 32 {
//         // 将读取到的字节数据编码为十六进制字符串
//         let found_key_str = hex::encode(&key_data);

//         // =======================================================
//         //           *** 这是关键的修改 ***
//         //  比较读取到的 key 是否与我们的“标准答案”匹配
//         // =======================================================
//         if found_key_str == TARGET_KEY {
//             // =======================================================
//             //           *** 这是关键的修改 ***
//             // 使用 fetch_add 来原子性地增加计数器并返回旧值
//             // Ordering::SeqCst 提供了最强的内存顺序保证，适合这种调试场景
//             // =======================================================
//             let validation_order = counter.fetch_add(1, Ordering::SeqCst);

//             // 我们在打印时 +1，因为 fetch_add 返回的是增加前的值 (从0开始)
//             println!(
//                 "\n🎉 [Validator] SUCCESS! I am the No.{} finder. Target key found at address {:#X}\n",
//                 validation_order + 1,
//                 addr
//             );
//             return Some(found_key_str);
//         } else {
//             // 如果不匹配，我们可以选择性地打印日志来观察找到了哪些“错误”的key
//             // 注意：这可能会产生大量日志
//             println!("[Validator] Mismatch. Found key: {} at address {:#X}", found_key_str, addr);
//         }
//     } else {
//         // 读取内存失败
//         // println!("[Validator] Failed to read memory at address {:#X}", addr);
//     }

//     // 如果不匹配或读取失败，则返回 None
//     None
// }

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