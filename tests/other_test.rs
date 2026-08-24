use std::ffi::c_void;
use windows::Win32::System::{Memory::PAGE_READWRITE, Threading::GetCurrentProcess};
use yapi::{Architecture, ProcessHandle, ProcessWriter, YapiArch};

#[test]
fn test_process_writer() {
    unsafe {
        let process = GetCurrentProcess();
        let data = vec![1u8, 2, 3, 4];
        let writer = ProcessWriter::new(process, &data, PAGE_READWRITE).unwrap();

        let mut read_back = vec![0u8; 4];
        let mut bytes_read = 0;

        let success = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            writer.address().as_ptr(),
            read_back.as_mut_ptr() as *mut c_void,
            4,
            Some(&mut bytes_read),
        );

        assert!(success.is_ok());
        assert_eq!(bytes_read, 4);
        assert_eq!(&read_back, &data);
    }
}

#[test]
fn test_get_module_handle_64_on_self() {
    // 자기 프로세스의 64비트 PEB를 순회해 ntdll을 찾는다 (GetModuleHandle64 포팅 검증)
    let arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
    let handle = unsafe { ProcessHandle::new(GetCurrentProcess(), arch) }.unwrap();

    let module = handle.get_module_handle_64("ntdll.dll").unwrap();
    assert!(module.base_address != 0, "ntdll base address is zero");
    assert!(module.size > 0, "ntdll size is zero");

    let func = handle
        .get_proc_address(module.base_address, "NtQueryInformationProcess")
        .unwrap();
    assert!(func > module.base_address, "export outside of module range");
}
#[test]
fn test_virtual_protect_on_self() {
    use windows::Win32::System::Memory::PAGE_READONLY;
    use windows::Win32::System::Threading::GetCurrentProcess;
    use yapi::{Architecture, ProcessHandle, ProcessWriter, YAPICall, YapiArch};

    unsafe {
        let data = [1u8, 2, 3, 4];
        let writer = ProcessWriter::new(GetCurrentProcess(), &data, PAGE_READWRITE).unwrap();

        let arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
        let ph = ProcessHandle::new(GetCurrentProcess(), arch).unwrap();
        let ntdll = ph.get_ntdll_64().unwrap();

        // virtual_protect는 YAPICall의 핸들 래퍼를 통해 동작한다
        let call = YAPICall::<()>::new_with_module_base(
            GetCurrentProcess(),
            ntdll,
            "NtGetCurrentProcessorNumber",
            true,
        )
        .unwrap();

        // 읽기 전용으로 바꿨다가 되돌린다
        let old = call
            .virtual_protect(writer.address().as_ptr() as u64, 4, PAGE_READONLY)
            .expect("virtual_protect failed");
        assert_eq!(old, PAGE_READWRITE);

        let restored = call
            .virtual_protect(writer.address().as_ptr() as u64, 4, PAGE_READWRITE)
            .expect("virtual_protect restore failed");
        assert_eq!(restored, PAGE_READONLY);
    }
}

#[test]
fn test_call_64bit_ntdll_function_in_self() {
    // 자기 프로세스가 대상이다.
    // - x64 빌드(네이티브): 64비트 함수 호출 성공
    // - i686 빌드(wow64 프로세스): wow64 대상의 64비트 함수 호출은 미지원 오류를 반환해야 함
    use windows::Win32::System::Threading::GetCurrentProcess;
    use yapi::YAPICall;

    unsafe {
        let mut call =
            YAPICall::<u32>::new_ntdll_64(GetCurrentProcess(), "NtGetCurrentProcessorNumber")
                .expect("new_ntdll_64 failed");

        match call.call_function(&[]) {
            Ok(n) => {
                println!("NtGetCurrentProcessorNumber = {n}");
                assert!(n < 65536);
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("WOW64"),
                    "unexpected error on wow64 self-call: {msg}"
                );
                println!("documented WOW64 limitation returned: {msg}");
            }
        }
    }
}
#[cfg(target_arch = "x86")]
#[test]
fn test_gate_suspended_thread_diag() {
    use windows::Win32::System::Threading::GetCurrentProcess;
    use yapi::{Architecture, ProcessHandle, YapiArch};

    unsafe {
        let arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
        let ph = ProcessHandle::new(GetCurrentProcess(), arch).unwrap();
        let base = ph.get_ntdll_64().unwrap();
        let f = ph
            .get_proc_address(base, "NtGetCurrentProcessorNumber")
            .unwrap();

        // 무해한 함수(프로세서 번호 반환)를 64비트 코드로 삼아 중지 스레드를 만든다.
        // f 주소의 코드는 NtGetCurrentProcessorNumber이므로 실행돼도 안전하다.
        let h = yapi::utils::x64_gate::create_remote_thread_64_suspended(
            GetCurrentProcess(),
            true,
            f,
            0,
        )
        .expect("suspended create failed");
        println!("suspended thread handle created: {:?}", h);
    }
}

#[test]
fn test_call_64bit_function_in_native_x64_target() {
    // 네이티브 x64 프로세스(explorer.exe)의 64비트 ntdll 함수를 원격 호출한다.
    // C++ 데모와 동일 시나리오. i686 빌드에서는 헤븐즈 게이트 경로가 검증된다.
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    };
    use yapi::YAPICall;

    unsafe {
        let snapshot = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
            0,
        )
        .unwrap();
        let _guard = scopeguard::guard(snapshot, |h| {
            let _ = CloseHandle(h);
        });

        let mut pe32: windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W =
            std::mem::zeroed();
        pe32.dwSize = std::mem::size_of::<
            windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W,
        >() as u32;

        let mut target: Option<HANDLE> = None;
        if windows::Win32::System::Diagnostics::ToolHelp::Process32FirstW(snapshot, &mut pe32)
            .is_ok()
        {
            loop {
                let name = String::from_utf16_lossy(
                    &pe32.szExeFile[..pe32
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(pe32.szExeFile.len())],
                );
                if name.eq_ignore_ascii_case("explorer.exe") {
                    if let Ok(h) = OpenProcess(PROCESS_ALL_ACCESS, false, pe32.th32ProcessID) {
                        target = Some(h);
                        break;
                    }
                }
                if !windows::Win32::System::Diagnostics::ToolHelp::Process32NextW(
                    snapshot, &mut pe32,
                )
                .is_ok()
                {
                    break;
                }
            }
        }

        let Some(handle) = target else {
            println!("explorer.exe not found; skipping");
            return;
        };

        let mut call = YAPICall::<u32>::new_ntdll_64(handle, "NtGetCurrentProcessorNumber")
            .expect("new_ntdll_64 failed");
        let r = call.call_function(&[]).expect("remote 64bit call failed");
        println!("remote processor number = {r}");
        assert!(r < 65536);

        CloseHandle(handle).unwrap();
    }
}
