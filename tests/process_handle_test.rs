use windows::Win32::System::Threading::GetCurrentProcess;
use yapi::{Architecture, ProcessHandle, YapiArch};

#[test]
fn test_get_module_handle() {
    let yapi_arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
    let handle = unsafe { GetCurrentProcess() };
    let process_handle = ProcessHandle::new(handle, yapi_arch).unwrap();

    let kernel32 = process_handle.get_module_handle("kernel32.dll").unwrap();
    assert_eq!(kernel32.name.to_uppercase(), "KERNEL32.DLL");
    assert!(kernel32.base_address > 0);
    assert!(kernel32.size > 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::c_void, time::Duration};
    use windows::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject};

    #[test]
    fn test_process_handle_creation() {
        unsafe {
            let process = GetCurrentProcess();
            let yapi_arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
            let handle = ProcessHandle::new(process, yapi_arch);
            assert!(handle.is_ok());
        }
    }

    #[test]
    fn test_module_handle() {
        unsafe {
            let process = GetCurrentProcess();
            let yapi_arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
            let handle = ProcessHandle::new(process, yapi_arch).unwrap();

            let module_info = handle.get_module_handle("ntdll.dll");
            assert!(module_info.is_ok());
            println!("ntdll.dll info: {:?}", module_info.unwrap());
        }
    }

    // #[test]
    // fn test_wow64_detection() {
    //     unsafe {
    //         let process = GetCurrentProcess();
    //         let yapi_arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
    //         let handle = ProcessHandle::new(process, yapi_arch).unwrap();

    //         let result = handle.is_wow64_process();
    //         assert!(result.is_ok());
    //         println!("Current process is WOW64: {}", result.unwrap());
    //     }
    // }

    #[test]
    fn test_thread_creation() {
        unsafe {
            let process = GetCurrentProcess();
            let yapi_arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
            let handle = ProcessHandle::new(process, yapi_arch).unwrap();

            // Simple thread that just returns 0
            extern "system" fn thread_proc(_: *mut c_void) -> u32 {
                0
            }

            let thread = handle
                .create_thread(false, None, thread_proc as *const () as u64, 0)
                .unwrap();

            let result = WaitForSingleObject(thread, Duration::from_secs(1).as_millis() as u32);
            let r = result.0;
            assert_eq!(r, 0);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_process_functions() {
        unsafe {
            let process = GetCurrentProcess();
            let yapi_arch = YapiArch::new(Architecture::X64, Architecture::X64, Architecture::X64);
            let handle = ProcessHandle::new(process, yapi_arch).unwrap();

            // Test getting module handle
            let ntdll = handle.get_module_handle("ntdll.dll").unwrap();
            assert!(ntdll.base_address > 0);

            // Test getting procedure address
            let get_proc_addr =
                handle.get_proc_address(ntdll.base_address, "NtQueryInformationProcess");
            assert!(get_proc_addr.is_ok());
            println!(
                "NtQueryInformationProcess address: 0x{:X}",
                get_proc_addr.unwrap()
            );
        }
    }
}
