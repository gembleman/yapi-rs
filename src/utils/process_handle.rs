use super::memory_reader::*;
use crate::{MemoryError, ProcessError, ThreadError, YapiError, types::*};
use std::{ffi::c_void, mem::zeroed};
use windows::{
    Win32::{
        Foundation::*,
        System::{
            Diagnostics::{Debug::*, ToolHelp::*},
            SystemServices::*,
            Threading::*,
        },
    },
    core::{PWSTR, s, w},
};

// RtlCreateUserThread function type definition
type RtlCreateUserThreadFn = unsafe extern "system" fn(
    process_handle: HANDLE,
    thread_security_descriptor: *const c_void,
    create_suspended: bool,
    zero_bits: u32,
    maximum_stack_size: *mut usize,
    committed_stack_size: *mut usize,
    start_address: usize,
    parameter: usize,
    thread_handle: *mut HANDLE,
    client_id: *mut c_void,
) -> NTSTATUS;

#[derive(Debug, Clone)]
pub struct ProcessHandle {
    handle: ProcessHandleWrapper,
    reader: ProcessReader,
    yapi_arch: YapiArch,
    rtl_create_user_thread: Option<RtlCreateUserThreadFn>,
}

impl ProcessHandle {
    pub fn new(handle: HANDLE, yapi_arch: YapiArch) -> Result<Self> {
        // NULL 핸들만 현재 프로세스로 대체한다.
        // INVALID 핸들은 그대로 통과시켜 이후 API 호출에서 오류로 드러나게 한다.
        let handle = if handle.0.is_null() {
            unsafe { GetCurrentProcess() }
        } else {
            handle
        };

        let reader = if yapi_arch.host_arch == Architecture::X64 {
            ProcessReader::Reader64(Process64Reader {
                process: handle.into(),
            })
        } else {
            ProcessReader::Reader32(Process32Reader {
                process: handle.into(),
            })
        };

        let rtl_create_user_thread = unsafe {
            // ntdll.dll 로드
            let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(w!("ntdll.dll"))?;

            // RtlCreateUserThread 함수 주소 가져오기
            let func: RtlCreateUserThreadFn = std::mem::transmute(
                windows::Win32::System::LibraryLoader::GetProcAddress(
                    ntdll,
                    s!("RtlCreateUserThread"),
                )
                .ok_or_else(|| {
                    YapiError::Process(ProcessError::FunctionNotFound {
                        name: "RtlCreateUserThread".to_string(),
                        module: "ntdll.dll".to_string(),
                    })
                })?,
            );
            Some(func)
        };

        Ok(Self {
            handle: handle.into(),
            reader,
            yapi_arch,
            rtl_create_user_thread,
        })
    }

    /// Create a remote thread using RtlCreateUserThread
    pub unsafe fn create_thread(
        &self,
        create_suspended: bool,
        stack_size: Option<usize>,
        start_address: u64,
        parameter: u64,
    ) -> Result<HANDLE> {
        let rtl_create_user_thread = self.rtl_create_user_thread.ok_or_else(|| {
            YapiError::Process(ProcessError::FunctionNotFound {
                name: "RtlCreateUserThread".to_string(),
                module: "ntdll.dll".to_string(),
            })
        })?;

        let mut thread_handle = HANDLE::default();
        let mut stack_size_value = stack_size.unwrap_or(0);

        #[cfg(debug_assertions)]
        {
            println!(
                "Creating thread - Process: {:?}, Address: 0x{:X}, Param: 0x{:X}",
                self.handle, start_address, parameter
            );
            println!(
                "start adr u32 : 0x{:X}, parameter u32 0x{:X}",
                start_address as u32, parameter as u32
            );
        }

        // C++ 구현과 동일하게 MaximumStackSize=NULL(기본 예약 크기),
        // CommittedStackSize=지정 값으로 전달한다
        let committed_stack_size_ptr = if stack_size.is_some() {
            &mut stack_size_value
        } else {
            std::ptr::null_mut()
        };

        #[cfg(target_arch = "x86")]
        if start_address > u32::MAX as u64 || parameter > u32::MAX as u64 {
            return Err(YapiError::Custom(
                "start address and parameter must be below 4GB on 32-bit hosts".to_string(),
            ));
        }

        let status = unsafe {
            rtl_create_user_thread(
                self.handle.into(),
                std::ptr::null(),     // lpThreadAttributes
                create_suspended,     // createSuspended
                0,                    // ZeroBits
                std::ptr::null_mut(), // MaximumStackSize (기본 예약 크기)
                committed_stack_size_ptr, // CommittedStackSize
                start_address as usize,
                parameter as usize,
                &mut thread_handle,
                std::ptr::null_mut(), // ClientId
            )
        };

        if status.is_ok() {
            Ok(thread_handle)
        } else {
            Err(YapiError::Thread(ThreadError::CreationFailed {
                reason: format!("RtlCreateUserThread failed with status: {:?}", status),
            }))
        }
    }

    pub fn get_module_handle(&self, module_name: &str) -> Result<ModuleInfo> {
        if module_name.is_empty() {
            return Err(YapiError::Process(ProcessError::ModuleNotFound {
                name: String::from("<empty>"),
            }));
        }

        match self.get_module_handle_with_snapshot(module_name) {
            Ok(info) => Ok(info),
            Err(_) => Err(YapiError::Process(ProcessError::ModuleNotFound {
                name: module_name.to_string(),
            })),
        }
    }
    fn get_module_handle_with_snapshot(&self, module_name: &str) -> Result<ModuleInfo> {
        unsafe {
            let process_id = GetProcessId(self.handle.into());
            let snapshot =
                CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)?;
            let mut me32: MODULEENTRY32W = zeroed();
            me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

            if !Module32FirstW(snapshot, &mut me32).is_ok() {
                CloseHandle(snapshot)?;
                return Err(YapiError::Process(ProcessError::ModuleNotFound {
                    name: module_name.to_string(),
                }));
            }

            let result = loop {
                let current_name = PWSTR::from_raw(me32.szModule.as_mut_ptr());
                if let Ok(current_str) = current_name.to_string() {
                    if current_str.to_uppercase() == module_name.to_uppercase() {
                        break Ok(ModuleInfo {
                            base_address: me32.modBaseAddr as u64,
                            size: me32.modBaseSize,
                            name: current_str,
                        });
                    }
                }

                if !Module32NextW(snapshot, &mut me32).is_ok() {
                    break Err(YapiError::Process(ProcessError::ModuleNotFound {
                        name: module_name.to_string(),
                    }));
                }
            };

            CloseHandle(snapshot)?;
            result
        }
    }

    pub fn get_proc_address(&self, module_base: u64, func_name: &str) -> Result<u64> {
        self.get_proc_address_remote(module_base, func_name)
    }

    fn get_proc_address_remote(&self, module_base: u64, func_name: &str) -> Result<u64> {
        if module_base == 0 || func_name.is_empty() {
            return Err(YapiError::Memory(MemoryError::OperationFailed {
                operation: "get_proc_address: invalid module base or empty function name".into(),
            }));
        }

        let idh: IMAGE_DOS_HEADER = self.reader.read(module_base)?;
        let idd = if self.yapi_arch.target_proc_arch == Architecture::X64 {
            let inh64: IMAGE_NT_HEADERS64 = self.reader.read(module_base + idh.e_lfanew as u64)?;
            inh64.OptionalHeader.DataDirectory[0]
        } else {
            let inh32: IMAGE_NT_HEADERS32 = self.reader.read(module_base + idh.e_lfanew as u64)?;
            inh32.OptionalHeader.DataDirectory[0]
        };

        if idd.VirtualAddress == 0 {
            return Err(YapiError::Memory(MemoryError::OperationFailed {
                operation: "get_proc_address: no export directory".into(),
            }));
        }

        let ied: IMAGE_EXPORT_DIRECTORY =
            self.reader.read(module_base + idd.VirtualAddress as u64)?;
        if ied.NumberOfNames == 0 || ied.NumberOfNames > 100_000 {
            return Err(YapiError::Memory(MemoryError::OperationFailed {
                operation: "get_proc_address: invalid number of names".into(),
            }));
        }

        let name_table: Vec<u32> = self.reader.read_array(
            module_base + ied.AddressOfNames as u64,
            ied.NumberOfNames as usize,
        )?;

        for i in 0..ied.NumberOfNames {
            // 개별 이름/서수 읽기 실패는 건너뛰고 계속 탐색한다 (C++ 구현과 동일)
            let func: Vec<u8> = match self
                .reader
                .read_array(module_base + name_table[i as usize] as u64, func_name.len())
            {
                Ok(v) => v,
                Err(_) => continue,
            };

            if func == func_name.as_bytes() {
                let ord: u16 = match self.reader.read(
                    module_base + ied.AddressOfNameOrdinals as u64 + i as u64 * 2,
                ) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let rva: u32 = match self.reader.read(
                    module_base + ied.AddressOfFunctions as u64 + ord as u64 * 4,
                ) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                return Ok(module_base + (rva as u64));
            }
        }

        Err(YapiError::Memory(MemoryError::OperationFailed {
            operation: "get_proc_address: function not found".into(),
        }))
    }

    /// Get the handle as HANDLE type
    pub fn as_raw(&self) -> HANDLE {
        self.handle.as_raw()
    }
}
