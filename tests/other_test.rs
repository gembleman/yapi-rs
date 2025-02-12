use std::ffi::c_void;
use windows::Win32::System::{Memory::PAGE_READWRITE, Threading::GetCurrentProcess};
use yapi::ProcessWriter;

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
fn test_module_enumeration() {
    // unsafe {
    //     // let process = GetCurrentProcess();
    //     // // let yapi = YAPICall::new(process, "kernel32.dll", "GetProcAddress").unwrap();
    //     // let modules = yapi.enum_modules().unwrap();

    //     // assert!(!modules.is_empty());
    //     // assert!(modules
    //     //     .iter()
    //     //     .any(|m| m.name.to_lowercase() == "kernel32.dll"));
    // }
}
