use std::time::Duration;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Memory::PAGE_READWRITE,
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
    UI::WindowsAndMessaging::MB_OK,
};
use yapi::{ProcessError, ProcessWriter, Result, YAPICall, YapiError};

/// Helper function to find a target process by name
unsafe fn find_target_process(target_process_name: &str) -> Result<(HANDLE, u32)> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    let _guard = scopeguard::guard(snapshot, |h| {
        let _ = unsafe { CloseHandle(h) };
    });

    let mut pe32: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot, &mut pe32) }.is_ok() {
        loop {
            let process_name = String::from_utf16_lossy(
                &pe32.szExeFile[..pe32
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe32.szExeFile.len())],
            );

            if process_name.to_lowercase() == target_process_name.to_lowercase() {
                // 프로세스를 찾았을 때 모든 필요한 권한으로 열기
                let process =
                    unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pe32.th32ProcessID) }?;
                return Ok((process, pe32.th32ProcessID));
            }

            if !unsafe { Process32NextW(snapshot, &mut pe32) }.is_ok() {
                break;
            }
        }
    }

    Err(YapiError::Process(ProcessError::OperationFailed {
        operation: "FindTargetProcess",
    }))
}

#[test]
fn test_wow64_injection() -> Result<()> {
    unsafe {
        //tests 폴더에 있는 test.exe를 실행.
        let _process = std::process::Command::new(
            "tests/x86-for-test/target/i686-pc-windows-msvc/release/x86-for-test.exe",
        )
        .spawn()
        .expect("Failed to start test process");

        // 대상 WOW64 프로세스 찾기
        let (process_handle, process_id) = find_target_process("x86-for-test.exe")?;
        println!("Process handle opened successfully. PID: {}", process_id);

        // MessageBoxA를 위한 YAPICall 초기화
        let mut message_box = YAPICall::<i32>::new(
            process_handle,
            "user32.dll",
            "MessageBoxA",
            false, // WOW64 함수 (32비트)
        )?
        .set_dw64_ret(false)
        .with_timeout(Duration::from_secs(500000));

        // 메시지와 캡션 문자열 준비 (NULL 종료 포함)
        let message = "MessageBoxA : Hello from Rust YAPI!\0";
        let caption = "WOW64 Test\0";

        // 대상 프로세스에 메모리 할당
        println!("Allocating memory for message and caption...");
        let message_mem = ProcessWriter::new(process_handle, message.as_bytes(), PAGE_READWRITE)?;
        let caption_mem = ProcessWriter::new(process_handle, caption.as_bytes(), PAGE_READWRITE)?;

        // MessageBoxA 파라미터 준비
        let params = vec![
            0u64,                                  // hWnd (NULL)
            message_mem.address().as_ptr() as u64, // lpText
            caption_mem.address().as_ptr() as u64, // lpCaption
            MB_OK.0 as u64,                        // uType
        ];

        // 디버그 출력
        println!("MessageBoxA parameters:");
        println!("  hWnd: NULL");
        println!("  lpText: 0x{:X}", message_mem.address().as_ptr() as u64);
        println!("  lpCaption: 0x{:X}", caption_mem.address().as_ptr() as u64);
        println!("  uType: MB_OK ({})", MB_OK.0);

        // 대상 프로세스에서 MessageBoxA 호출
        println!("Executing MessageBoxA in target process...");
        let result = message_box.call_function(&params)?;
        println!("MessageBoxA returned: {}", result);

        // 정리
        CloseHandle(process_handle)?;

        Ok(())
    }
}

// 메모리 할당 검증을 위한 추가 테스트
#[test]
fn test_process_writer_wow64() -> Result<()> {
    unsafe {
        let (process_handle, _) = find_target_process("x86-for-test.exe")?;
        let test_data = "Test Data\0";

        let writer = ProcessWriter::new(process_handle, test_data.as_bytes(), PAGE_READWRITE)?;
        assert!(writer.address().as_ptr() != std::ptr::null_mut());

        // WOW64 프로세스에서 메모리가 올바르게 할당되었는지 확인
        let address = writer.address().as_ptr() as u64;
        assert!(
            address < 0x100000000,
            "Memory allocated above 4GB in WOW64 process"
        );

        println!("Memory allocated at 0x{:X}", address);

        // std::thread::sleep(Duration::from_secs(10000));

        CloseHandle(process_handle)?;
        Ok(())
    }
}

// 프로세스 검색 테스트
#[test]
fn test_find_process() -> Result<()> {
    unsafe {
        let (handle, pid) = find_target_process("x86-for-test.exe")?;
        println!("Found test process. PID: {}", pid);
        assert!(pid > 0, "Invalid process ID");
        CloseHandle(handle)?;
        Ok(())
    }
}
