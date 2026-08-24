use std::{
    process::Stdio,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
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
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
        return Err(YapiError::Process(ProcessError::OperationFailed {
            operation: "CreateToolhelp32Snapshot",
        }));
    }
    let _guard = scopeguard::guard(snapshot, |h| {
        let _ = unsafe { CloseHandle(h) };
    });

    let mut pe32: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot, &mut pe32) } != 0 {
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
                let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pe32.th32ProcessID) };
                if process.is_null() {
                    continue;
                }
                return Ok((process, pe32.th32ProcessID));
            }

            if unsafe { Process32NextW(snapshot, &mut pe32) } == 0 {
                break;
            }
        }
    }

    Err(YapiError::Process(ProcessError::OperationFailed {
        operation: "FindTargetProcess",
    }))
}

/// x86 테스트 대상 실행 파일 경로를 찾는다.
/// 환경 변수 YAPI_TEST_X86_EXE로 겹쳐 쓸 수 있다.
fn x86_test_exe_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("YAPI_TEST_X86_EXE") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/x86-for-test/target/i686-pc-windows-msvc/release/x86-for-test.exe");
    p.is_file().then_some(p)
}

/// 테스트 바이너리가 직접 띄운 대상 프로세스를 스위트 동안 유지한다.
static SPAWNED_CHILD: OnceLock<Mutex<Option<std::process::Child>>> = OnceLock::new();

fn spawned_child_slot() -> &'static Mutex<Option<std::process::Child>> {
    SPAWNED_CHILD.get_or_init(|| Mutex::new(None))
}

/// 현재 대상을 쓰는 테스트 수. 0으로 내려가면 직접 띄운 프로세스를 정리한다.
static TARGET_USERS: AtomicUsize = AtomicUsize::new(0);

/// 대상 사용이 끝나면 사용 수를 줄이고, 마지막 사용자라면
/// 직접 띄운 대상 프로세스를 정리한다 (스위트 종료 시 잔류 프로세스 방지).
struct TargetGuard;

impl TargetGuard {
    fn acquire() -> Self {
        TARGET_USERS.fetch_add(1, Ordering::SeqCst);
        TargetGuard
    }
}

impl Drop for TargetGuard {
    fn drop(&mut self) {
        if TARGET_USERS.fetch_sub(1, Ordering::SeqCst) != 1 {
            return;
        }
        let Some(slot) = SPAWNED_CHILD.get() else {
            return;
        };
        let mut child_slot = slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut child) = child_slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// 32비트 테스트 대상을 확보한다. 실행 중이면 재사용하고, 아니면 새로 띄운다.
/// 확보 불가(실행 파일 없음 등)면 None을 반환해 테스트를 건너뛴다.
/// 뮤텍스로 직렬화해 병렬 테스트의 이중 스폰을 막는다.
unsafe fn ensure_x86_target() -> Result<Option<(HANDLE, u32, TargetGuard)>> {
    unsafe {
        let mut slot = spawned_child_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // 실행 중인 대상이 있으면 재사용한다 (외부 인스턴스 포함)
        if let Ok((process, pid)) = find_target_process("x86-for-test.exe") {
            return Ok(Some((process, pid, TargetGuard::acquire())));
        }

        let Some(exe_path) = x86_test_exe_path() else {
            eprintln!("x86-for-test.exe를 찾을 수 없어 테스트를 건너뛴다");
            return Ok(None);
        };

        // 새로 띄운다. 잠금 구간 안에서만 스폰하므로 이중 스폰이 없다.
        // 파이프 핸들 상속은 cargo가 테스트 종료 후에도 대기를 하게 만드므로 끊는다
        let child = std::process::Command::new(&exe_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| YapiError::Custom(format!("테스트 대상 시작 실패: {e}")))?;
        *slot = Some(child);

        // 스냅샷에 보일 때까지 잠깐 기다린다
        for _ in 0..50 {
            if let Ok((process, pid)) = find_target_process("x86-for-test.exe") {
                return Ok(Some((process, pid, TargetGuard::acquire())));
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(YapiError::Process(ProcessError::OperationFailed {
            operation: "FindTargetProcessAfterSpawn",
        }))
    }
}

/// 대화형 테스트: 대상 프로세스에 MessageBoxA를 띄우고 사람이 확인을 누를 때까지
/// 멈춘다(타임아웃 약 5.8일). 기본 스위트에서는 제외되며 아래처럼 따로 실행한다.
///
/// ```text
/// cargo test --target x86_64-pc-windows-msvc --test x64_host_wow64_target_test -- --ignored
/// ```
#[ignore]
#[test]
fn test_wow64_injection() -> Result<()> {
    unsafe {
        // 32비트 테스트 대상을 확보한다 (실행 중이면 재사용)
        let Some((process_handle, process_id, _target_guard)) = ensure_x86_target()? else {
            return Ok(());
        };
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
            MB_OK as u64,                          // uType
        ];

        // 디버그 출력
        println!("MessageBoxA parameters:");
        println!("  hWnd: NULL");
        println!("  lpText: 0x{:X}", message_mem.address().as_ptr() as u64);
        println!("  lpCaption: 0x{:X}", caption_mem.address().as_ptr() as u64);
        println!("  uType: MB_OK ({})", MB_OK);

        // 대상 프로세스에서 MessageBoxA 호출
        println!("Executing MessageBoxA in target process...");
        let result = message_box.call_function(&params)?;
        println!("MessageBoxA returned: {}", result);

        // 정리
        assert_ne!(CloseHandle(process_handle), 0);

        Ok(())
    }
}

// 메모리 할당 검증을 위한 추가 테스트
#[test]
fn test_process_writer_wow64() -> Result<()> {
    unsafe {
        let Some((process_handle, _, _target_guard)) = ensure_x86_target()? else {
            return Ok(());
        };
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

        assert_ne!(CloseHandle(process_handle), 0);
        Ok(())
    }
}

// 프로세스 검색 테스트
#[test]
fn test_find_process() -> Result<()> {
    unsafe {
        let Some((handle, pid, _target_guard)) = ensure_x86_target()? else {
            return Ok(());
        };
        println!("Found test process. PID: {}", pid);
        assert!(pid > 0, "Invalid process ID");
        assert_ne!(CloseHandle(handle), 0);
        Ok(())
    }
}
