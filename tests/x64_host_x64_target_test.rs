use std::ffi::c_void;

use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::{
            Debug::ReadProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
        },
        Memory::PAGE_READWRITE,
        Threading::{IsWow64Process, OpenProcess, PROCESS_ALL_ACCESS},
    },
};
use yapi::{
    Architecture, ProcessError, ProcessHandle, ProcessWriter, Result, YAPICall, YapiArch, YapiError,
};

// Helper function to find Explorer process
pub unsafe fn find_explorer_process(target_process_name: &str) -> Result<(HANDLE, u32)> {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
    let mut pe32: PROCESSENTRY32W = std::mem::zeroed();
    pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if Process32FirstW(snapshot, &mut pe32).is_ok() {
        loop {
            let process_name = String::from_utf16_lossy(
                &pe32.szExeFile[..pe32
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe32.szExeFile.len())],
            );

            if process_name.to_lowercase() == target_process_name {
                let process = OpenProcess(PROCESS_ALL_ACCESS, false, pe32.th32ProcessID)?;
                return Ok((process, pe32.th32ProcessID));
            }

            if !Process32NextW(snapshot, &mut pe32).is_ok() {
                break;
            }
        }
    }

    Err(YapiError::Process(ProcessError::OperationFailed {
        operation: "FindExplorerProcess",
    }))
}

#[test]
fn test_message_box() -> Result<()> {
    unsafe {
        let (process, pid) = find_explorer_process("explorer.exe")?;
        println!("[{}] explorer.exe process found", pid);

        // Check process access rights
        // let access_rights = QueryFullProcessImageNameW(process, 0, None, None)?;
        // println!("Process path: {:?}", access_rights);

        // MessageBoxA test
        let mut msg_box_a = YAPICall::<i32>::new(process, "user32.dll", "MessageBoxA", false)?
            .with_timeout(std::time::Duration::from_secs(50));

        // Explicitly check memory allocation permissions
        let message_str = "MessageBoxA : Hello World!\0";
        let caption_str = "From Rust YAPI\0";

        println!("Attempting to allocate memory for message");
        let message = ProcessWriter::new(process, message_str.as_bytes(), PAGE_READWRITE)?;

        println!("Attempting to allocate memory for caption");
        let caption = ProcessWriter::new(process, caption_str.as_bytes(), PAGE_READWRITE)?;

        // Get pointers to the strings in target process memory
        let text_ptr = message.address().as_ptr() as u64;
        let caption_ptr = caption.address().as_ptr() as u64;

        println!(
            "MessageBoxA text_ptr: 0x{:X}, caption_ptr: 0x{:X}",
            text_ptr, caption_ptr
        );

        // Verify memory contents
        let mut verify_buffer = vec![0u8; message_str.len()];
        let mut bytes_read = 0;
        let read_result = ReadProcessMemory(
            process,
            text_ptr as *const c_void,
            verify_buffer.as_mut_ptr() as *mut c_void,
            verify_buffer.len(),
            Some(&mut bytes_read),
        );

        println!("Memory read result: {:?}", read_result);
        println!("Bytes read: {}", bytes_read);
        println!(
            "Verified message: {:?}",
            String::from_utf8_lossy(&verify_buffer)
        );

        // Print the parameters for debugging
        println!("Parameters:");
        println!("  hWnd: 0");
        println!("  lpText: 0x{:X}", text_ptr);
        println!("  lpCaption: 0x{:X}", caption_ptr);
        println!("  uType: 0");

        let result: i32 = msg_box_a.call_function(&[
            0,           // hWnd = NULL
            text_ptr,    // lpText
            caption_ptr, // lpCaption
            0,           // MB_OK
        ])?;

        println!("MessageBoxA result: {} (0x{:X})", result, result as u32);

        // More detailed error checking
        if result == -1073741819 {
            println!("Access Violation Error (0xC0000005)");

            // Additional diagnostic information
            println!("Function Address: 0x{:X}", msg_box_a.function_address);

            // Optional: Virtual memory query for the text and caption pointers
            let text_mbi = msg_box_a.virtual_query(text_ptr)?;
            let caption_mbi = msg_box_a.virtual_query(caption_ptr)?;

            println!("Text Pointer Memory Info:");
            println!("  Base Address: 0x{:X}", text_mbi.BaseAddress as u64);
            println!("  Allocation Base: 0x{:X}", text_mbi.AllocationBase as u64);
            println!("  Allocation Protect: {:?}", text_mbi.AllocationProtect);
            println!("  State: {:?}", text_mbi.State);

            println!("Caption Pointer Memory Info:");
            println!("  Base Address: 0x{:X}", caption_mbi.BaseAddress as u64);
            println!(
                "  Allocation Base: 0x{:X}",
                caption_mbi.AllocationBase as u64
            );
            println!("  Allocation Protect: {:?}", caption_mbi.AllocationProtect);
            println!("  State: {:?}", caption_mbi.State);
        }

        assert!(result == 1 || result == 0, "Unexpected MessageBoxA result");
        Ok(())
    }
}

#[test]
fn test_get_process_id() -> Result<()> {
    unsafe {
        let (process, pid) = find_explorer_process("explorer.exe")?;

        // Create YAPICall instance for GetCurrentProcessId
        let mut get_pid =
            YAPICall::<u32>::new(process, "kernel32.dll", "GetCurrentProcessId", false)?;

        // Call the function - it takes no parameters
        let target_pid = get_pid.call_function(&[])?;

        println!("[{}] explorer.exe => {}", pid, target_pid);
        assert!(target_pid > 0);
        Ok(())
    }
}

// #[test]
// fn test_load_library() -> Result<()> {
//     unsafe {
//         let (process, pid) = find_explorer_process()?;
//         println!("[{}] Testing LoadLibrary", pid);

//         // Create YAPICall instance for LoadLibraryA
//         let mut load_lib = YAPICall::<u64>::new(process, "kernel32.dll", "LoadLibraryA", false)?;

//         // Test loading x86.dll (requires dll at D:\x86.dll)
//         let x86_path = ProcessWriter::new(process, "D:\\x86.dll\0".as_bytes(), PAGE_READWRITE)?;
//         let x86_result = load_lib.call_x64_func(&[x86_path.address().as_ptr() as u64])?;
//         println!("X86: {:#x}", x86_result);

//         // Test loading x64.dll (requires dll at D:\x64.dll)
//         let x64_path = ProcessWriter::new(process, "D:\\x64.dll\0".as_bytes(), PAGE_READWRITE)?;

//         // Set 64-bit return value flag and call
//         let x64_result = load_lib
//             .set_dw64_ret(true)
//             .call_x64_func(&[x64_path.address().as_ptr() as u64])?;
//         println!("X64: {:#x}", x64_result);

//         Ok(())
//     }
// }

#[test]
fn test_module_enumeration() -> Result<()> {
    unsafe {
        let (process, pid) = find_explorer_process("explorer.exe")?;
        println!("[{}] Testing module enumeration", pid);

        // Check if target process is WOW64
        let mut is_wow64 = false.into();
        IsWow64Process(process, &mut is_wow64)?;
        let target_arch = if is_wow64.as_bool() {
            Architecture::X86
        } else {
            Architecture::X64
        };

        // Create ProcessHandle with correct architecture
        let handle = ProcessHandle::new(
            process,
            YapiArch::new(Architecture::X64, target_arch, target_arch),
        )?;

        // Get kernel32.dll module info
        let module_info = handle.get_module_handle("kernel32.dll")?;
        println!("kernel32.dll base address: {:#x}", module_info.base_address);
        assert!(module_info.base_address > 0);

        // Get GetCurrentProcessId function address
        let proc_addr =
            handle.get_proc_address(module_info.base_address, "GetCurrentProcessId\0")?;
        println!("GetCurrentProcessId address: {:#x}", proc_addr);
        assert!(proc_addr > 0);

        Ok(())
    }
}
