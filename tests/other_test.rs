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
