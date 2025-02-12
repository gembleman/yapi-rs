use crate::error::*;
use crate::types::*;
use crate::utils::*;
use crate::Architecture::*;
use crate::ProcessWriter;
use crate::ShellCodeBuilder;

use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::zeroed;
use std::time::Duration;
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::{
    Foundation::{CloseHandle, FALSE, HANDLE},
    System::{
        Diagnostics::{Debug::ReadProcessMemory, ToolHelp::*},
        Memory::*,
        SystemInformation::*,
        Threading::*,
    },
};

#[derive(Debug, Clone)]
pub struct YAPICall<R = u64> {
    pub target_process_handle: ProcessHandle,
    pub shell_code_memory: Option<ProcessWriter>,
    pub function_address: u64,
    pub dw64_ret: bool,
    pub timeout: Option<Duration>,
    pub yapi_arch: YapiArch,
    pub _phantom: PhantomData<R>,
}

impl<R> YAPICall<R>
where
    R: Copy + 'static + Default + std::fmt::Debug,
{
    pub fn set_target_proc_arch(&mut self, target_proc_arch: Architecture) {
        self.yapi_arch.target_proc_arch = target_proc_arch;
    }

    pub fn set_host_arch(&mut self, host_arch: Architecture) {
        self.yapi_arch.host_arch = host_arch;
    }

    pub fn set_func_arch(&mut self, func_arch: Architecture) {
        self.yapi_arch.func_arch = func_arch;
    }

    /// is_64bit_func is only use when target_process is 32bit and function is 64bit
    pub fn new(
        target_process: HANDLE,
        module_name: &str,
        func_name: &str,
        is_64bit_func: bool,
    ) -> Result<Self> {
        // 호스트 프로세스 아키텍처 감지
        let host_arch = unsafe {
            let mut si: SYSTEM_INFO = zeroed();
            GetNativeSystemInfo(&mut si);
            match si.Anonymous.Anonymous.wProcessorArchitecture {
                PROCESSOR_ARCHITECTURE_AMD64 | PROCESSOR_ARCHITECTURE_IA64 => X64,
                _ => X86,
            }
        };

        // 프로세스 아키텍처 감지
        let target_proc_arch = unsafe {
            let mut is_wow64 = FALSE;
            match IsWow64Process(target_process, &mut is_wow64) {
                Ok(_) if host_arch == X64 && is_wow64.as_bool() => X86,
                _ => host_arch,
            }
        };

        // 함수 아키텍처 결정 - WOW64 함수는 항상 32비트 // is_64bit_func이 true이면 64비트 함수라 간주
        let func_arch = if is_64bit_func { X64 } else { target_proc_arch };

        let yapi_arch = YapiArch::new(host_arch, target_proc_arch, func_arch);
        let target_process_handle = ProcessHandle::new(target_process, yapi_arch)?;

        #[cfg(debug_assertions)]
        println!("Looking for module {} ({:?})", module_name, func_arch);

        let module_info = target_process_handle.get_module_handle(module_name)?;
        let function_address =
            target_process_handle.get_proc_address(module_info.base_address, func_name)?;

        #[cfg(debug_assertions)]
        println!(
            "Found function {} at 0x{:X} in {} (arch: {:?})",
            func_name, function_address, module_info.name, func_arch
        );

        // 함수 주소 유효성 검사
        if function_address == 0 {
            return Err(YapiError::Process(ProcessError::FunctionNotFound {
                name: func_name.to_string(),
                module: module_info.name,
            }));
        }

        Ok(Self {
            target_process_handle,
            shell_code_memory: None,
            function_address,
            dw64_ret: false,
            timeout: Some(Duration::from_secs(5)),
            yapi_arch,
            _phantom: PhantomData,
        })
    }

    pub fn call_function(&mut self, params: &[u64]) -> Result<R> {
        if self.function_address == 0 {
            return Err(YapiError::Memory(MemoryError::OperationFailed {
                operation: "GetProcAddress".into(),
            }));
        }

        unsafe {
            // 쉘코드 초기화
            self.init_shell_code(params.len() as u8)?;

            // 3. 파라미터 버퍼 준비
            let param_buffer = self.prepare_params(params)?;

            #[cfg(debug_assertions)]
            {
                // 파라미터 버퍼 상세 덤프
                println!("Param Buffer Details:");

                // 안전한 메모리 읽기 방법
                let buffer_bytes = {
                    let mut buffer = vec![0u8; param_buffer.size];
                    let mut bytes_read = 0;

                    ReadProcessMemory(
                        self.target_process_handle.as_raw(),
                        param_buffer.address().as_ptr(),
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len(),
                        Some(&mut bytes_read),
                    )?;

                    buffer
                };

                println!(
                    "Raw Buffer (bytes): {}",
                    buffer_bytes
                        .iter()
                        .map(|b| format!("0x{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                // 추가적으로 읽은 바이트 수도 출력하면 디버깅에 도움이 됩니다
                println!("Bytes read from param buffer: {}", buffer_bytes.len());

                // 쉘코드 메모리 정보 출력
                if let Some(shell_code_mem) = &self.shell_code_memory {
                    println!(
                        "Shell Code Memory Address: 0x{:X}",
                        shell_code_mem.address().as_ptr() as u64
                    );
                    println!("Shell Code Size: {}", shell_code_mem.size);
                }
            }

            // 4. 원격 스레드 실행
            self.execute_remote_thread(param_buffer.address().as_ptr())
            // Ok(R::default())
        }
    }

    unsafe fn execute_remote_thread(&mut self, param_address: *mut c_void) -> Result<R> {
        let shell_code_addr = self.shell_code_memory.as_ref().unwrap().address().as_ptr() as u64;

        let thread_handle = match self.yapi_arch.host_arch {
            Architecture::X86 => {
                match (self.yapi_arch.target_proc_arch, self.yapi_arch.func_arch) {
                    // 호스트가 32비트이고, 타깃 프로세스가 32비트, 함수가 32비트인 경우, 쉘코드도 32비트.
                    (Architecture::X86, Architecture::X86) => {
                        #[cfg(debug_assertions)]
                        println!("host is 32bit func is 32");
                        self.target_process_handle.create_thread(
                            false,
                            None,
                            self.shell_code_memory.as_ref().unwrap().address().as_ptr() as u32
                                as u64,
                            param_address as u32 as u64,
                        )?
                    }
                    //WOW64(32비트) 호스트에서 64비트 타겟 프로세스의 64비트 API를 호출할 때
                    (Architecture::X64, Architecture::X64) => {
                        #[cfg(debug_assertions)]
                        println!("host is wow64 func is 64");

                        pub const X64_CALL: &[u8] = &[
                            0x55, 0x8b, 0xec, 0x8b, 0x4d, 0x10, 0x8d, 0x55, 0x14, 0x83, 0xec, 0x40,
                            0x53, 0x56, 0x57, 0x85, 0xc9, 0x7e, 0x15, 0x8b, 0x45, 0x14, 0x8d, 0x55,
                            0x1c, 0x49, 0x89, 0x45, 0xf0, 0x8b, 0x45, 0x18, 0x89, 0x4d, 0x10, 0x89,
                            0x45, 0xf4, 0xeb, 0x08, 0x0f, 0x57, 0xc0, 0x66, 0x0f, 0x13, 0x45, 0xf0,
                            0x85, 0xc9, 0x7e, 0x15, 0x49, 0x83, 0xc2, 0x08, 0x89, 0x4d, 0x10, 0x8b,
                            0x42, 0xf8, 0x89, 0x45, 0xe8, 0x8b, 0x42, 0xfc, 0x89, 0x45, 0xec, 0xeb,
                            0x08, 0x0f, 0x57, 0xc0, 0x66, 0x0f, 0x13, 0x45, 0xe8, 0x85, 0xc9, 0x7e,
                            0x15, 0x49, 0x83, 0xc2, 0x08, 0x89, 0x4d, 0x10, 0x8b, 0x42, 0xf8, 0x89,
                            0x45, 0xe0, 0x8b, 0x42, 0xfc, 0x89, 0x45, 0xe4, 0xeb, 0x08, 0x0f, 0x57,
                            0xc0, 0x66, 0x0f, 0x13, 0x45, 0xe0, 0x85, 0xc9, 0x7e, 0x15, 0x49, 0x83,
                            0xc2, 0x08, 0x89, 0x4d, 0x10, 0x8b, 0x42, 0xf8, 0x89, 0x45, 0xd8, 0x8b,
                            0x42, 0xfc, 0x89, 0x45, 0xdc, 0xeb, 0x08, 0x0f, 0x57, 0xc0, 0x66, 0x0f,
                            0x13, 0x45, 0xd8, 0x8b, 0xc2, 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00,
                            0x99, 0x0f, 0x57, 0xc0, 0x89, 0x45, 0xc0, 0x8b, 0xc1, 0x89, 0x55, 0xc4,
                            0x99, 0x66, 0x0f, 0x13, 0x45, 0xc8, 0x89, 0x45, 0xd0, 0x89, 0x55, 0xd4,
                            0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x8c, 0x65, 0xf8, 0xb8,
                            0x2b, 0x00, 0x00, 0x00, 0x66, 0x8e, 0xe0, 0x89, 0x65, 0xfc, 0x83, 0xe4,
                            0xf0, 0x6a, 0x33, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05,
                            0xcb, 0x48, 0x8b, 0x4d, 0xf0, 0x48, 0x8b, 0x55, 0xe8, 0xff, 0x75, 0xe0,
                            0x49, 0x58, 0xff, 0x75, 0xd8, 0x49, 0x59, 0x48, 0x8b, 0x45, 0xd0, 0xa8,
                            0x01, 0x75, 0x03, 0x83, 0xec, 0x08, 0x57, 0x48, 0x8b, 0x7d, 0xc0, 0x48,
                            0x85, 0xc0, 0x74, 0x16, 0x48, 0x8d, 0x7c, 0xc7, 0xf8, 0x48, 0x85, 0xc0,
                            0x74, 0x0c, 0xff, 0x37, 0x48, 0x83, 0xef, 0x08, 0x48, 0x83, 0xe8, 0x01,
                            0xeb, 0xef, 0x48, 0x83, 0xec, 0x20, 0xff, 0x55, 0x08, 0x48, 0x8b, 0x4d,
                            0xd0, 0x48, 0x8d, 0x64, 0xcc, 0x20, 0x5f, 0x48, 0x89, 0x45, 0xc8, 0xe8,
                            0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,
                            0x83, 0x04, 0x24, 0x0d, 0xcb, 0x66, 0x8c, 0xd8, 0x66, 0x8e, 0xd0, 0x8b,
                            0x65, 0xfc, 0x66, 0x8b, 0x45, 0xf8, 0x66, 0x8e, 0xe0, 0x8b, 0x45, 0xc8,
                            0x8b, 0x55, 0xcc, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3,
                        ];

                        let bridge_code_mem = ProcessWriter::new(
                            self.target_process_handle.as_raw(),
                            &X64_CALL,
                            PAGE_EXECUTE_READWRITE,
                        )?;

                        self.target_process_handle.create_thread(
                            false,
                            None,
                            bridge_code_mem.address().as_ptr() as u64,
                            param_address as u32 as u64,
                        )?
                    }
                    _ => {
                        return Err(YapiError::Custom(
                            "32-bit host cannot call 64-bit function".to_string(),
                        ));
                    }
                }
            }
            Architecture::X64 => {
                match (self.yapi_arch.target_proc_arch, self.yapi_arch.func_arch) {
                    // 호스트가 64비트이고, 타깃 프로세스가 32비트, 함수가 32비트인 경우, 쉘코드도 32비트.
                    (Architecture::X86, Architecture::X86) => {
                        #[cfg(debug_assertions)]
                        println!("host is 64bit func is wow32");
                        CreateRemoteThread(
                            self.target_process_handle.as_raw(),
                            None,
                            0,
                            Some(std::mem::transmute(shell_code_addr)),
                            Some(param_address),
                            0,
                            None,
                        )?
                    }
                    // 호스트가 64비트이고, 타깃 프로세스가 32비트(wow64), 함수가 64비트인 경우, 쉘코드도 32비트. - 브릿지 코드 사용.
                    (Architecture::X86, Architecture::X64) => {
                        #[cfg(debug_assertions)]
                        println!("host is 64bit func is 64");

                        // 64비트 호스트에서
                        // 32비트 프로세스에
                        // 64비트 API 호출을 시도할 때만 사용됩니다
                        pub const K_TMPL_X64_TO_X86: &[u8] = &[
                            0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x44,
                            0x24, 0x30, 0x8b, 0x48, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x30, 0x6a, 0x33,
                            0xe8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xcb, 0xff, 0xd0,
                            0xe8, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00,
                            0x00, 0x83, 0x04, 0x24, 0x0d, 0xcb, 0x48, 0x83, 0xc4, 0x28, 0xc3,
                        ];

                        let bridge_code_mem = ProcessWriter::new(
                            self.target_process_handle.as_raw(),
                            &K_TMPL_X64_TO_X86,
                            PAGE_EXECUTE_READWRITE,
                        )?;
                        CreateRemoteThread(
                            self.target_process_handle.as_raw(),
                            None,
                            0,
                            Some(std::mem::transmute(bridge_code_mem.address().as_ptr())),
                            Some(param_address),
                            0,
                            None,
                        )?
                    }

                    // 호스트가 64비트이고, 타깃 프로세스가 64비트, 함수도 64비트인 경우, 쉘코드도 64비트.
                    (Architecture::X64, Architecture::X64) => {
                        #[cfg(debug_assertions)]
                        println!("host is 64bit func is 64");
                        println!("shell_code_addr: 0x{:X}", shell_code_addr);

                        CreateRemoteThread(
                            self.target_process_handle.as_raw(),
                            None,
                            0,
                            Some(std::mem::transmute(shell_code_addr)),
                            Some(param_address),
                            0,
                            None,
                        )?
                    }
                    // 호스트가 64비트이고, 타깃 프로세스가 64비트, 함수가 32비트인 경우, 에러.
                    (Architecture::X64, Architecture::X86) => {
                        return Err(YapiError::Custom(
                            "64-bit host cannot call 32-bit function in 64-bit process".to_string(),
                        ));
                    }
                }
            }
        };

        let timeout_ms = self
            .timeout
            .map(|d| d.as_millis() as u32)
            .unwrap_or(INFINITE);

        if WaitForSingleObject(thread_handle, timeout_ms) != WAIT_OBJECT_0 {
            self.shell_code_memory.as_mut().map(|sc| sc.dont_free());
            CloseHandle(thread_handle)?;
            return Err(YapiError::Thread(ThreadError::TimeoutError {
                ms: timeout_ms,
            }));
        }

        let result = if self.yapi_arch.host_arch == Architecture::X86 || !self.dw64_ret {
            // 32비트 또는 dw64_ret이 false인 경우
            let mut exit_code = 0u32;
            GetExitCodeThread(thread_handle, &mut exit_code)?;
            unsafe { std::mem::transmute_copy(&exit_code) }
        } else {
            // 64비트이고 dw64_ret이 true인 경우
            let mut result: R = R::default();
            ReadProcessMemory(
                self.target_process_handle.as_raw(),
                param_address,
                &mut result as *mut R as *mut c_void,
                std::mem::size_of::<R>(),
                None,
            )?;
            result
        };

        CloseHandle(thread_handle)?;
        Ok(result)
    }

    fn init_shell_code(&mut self, arg_count: u8) -> Result<()> {
        // 인자 개수 제한 체크
        if arg_count > 6 {
            return Err(YapiError::Custom(
                "Maximum 6 parameters supported".to_string(),
            ));
        }

        // 이미 쉘코드가 있다면 재사용
        if self.shell_code_memory.is_some() {
            return Ok(());
        }

        // 새 쉘코드 생성
        let code: Vec<u8> = ShellCodeBuilder::new(self.yapi_arch)
            .make_shell_code(arg_count)
            .build();

        #[cfg(debug_assertions)]
        println!(
            "Shell code: {:?}",
            code.iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );

        // 쉘코드를 대상 프로세스 메모리에 쓰기
        self.shell_code_memory = Some(ProcessWriter::new(
            self.target_process_handle.as_raw(),
            &code,
            PAGE_EXECUTE_READWRITE, // PAGE_EXECUTE_READWRITE
        )?);

        #[cfg(debug_assertions)]
        println!(
            "Shell code memory allocated at 0x{:X}",
            self.shell_code_memory.as_ref().unwrap().address().as_ptr() as u64
        );
        // std::thread::sleep(Duration::from_secs(1));

        Ok(())
    }

    unsafe fn prepare_params(&self, params: &[u64]) -> Result<ProcessWriter> {
        let mut buffer = Vec::new();
        let initial_size = match self.yapi_arch.func_arch {
            X86 => 4 + (params.len() * 4), // 함수 포인터(4) + 파라미터들(4 * n)
            X64 => 8 + 8 + (params.len() * 8), // dw64_ret(8) + 함수 포인터(8) + 파라미터들(8 * n)
        };
        buffer.resize(initial_size, 0);

        match self.yapi_arch.func_arch {
            X86 => {
                // 32비트 함수 포인터가 첫 번째 위치에 와야 함
                buffer.insert_slice(0, &(self.function_address as u32).to_le_bytes());
                let mut offset = 4;
                // 그 다음에 파라미터들
                for &param in params {
                    buffer.insert_slice(offset, &(param as u32).to_le_bytes());
                    offset += 4;
                }
            }
            X64 => {
                // 64비트는 그대로
                buffer.insert_slice(0, &(self.dw64_ret as u64).to_le_bytes());
                buffer.insert_slice(8, &self.function_address.to_le_bytes());
                let mut offset = 16;
                for &param in params {
                    buffer.insert_slice(offset, &param.to_le_bytes());
                    offset += 8;
                }
            }
        }

        ProcessWriter::new(self.target_process_handle.as_raw(), &buffer, PAGE_READWRITE)
    }
    pub fn set_dw64_ret(mut self, dw64_ret: bool) -> Self {
        self.dw64_ret = dw64_ret;
        self
    }

    pub fn with_timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    pub fn virtual_query(&self, address: u64) -> Result<MEMORY_BASIC_INFORMATION> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

            if VirtualQueryEx(
                self.target_process_handle.as_raw(),
                Some(address as *const c_void),
                &mut mbi,
                size,
            ) == 0
            {
                return Err(YapiError::Memory(MemoryError::ReadFailed { address, size }));
            }

            Ok(mbi)
        }
    }

    pub fn enum_modules(&self) -> Result<Vec<ModuleInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                GetCurrentProcessId(),
            )?;

            let _guard = scopeguard::guard(snapshot, |h| {
                let _ = CloseHandle(h);
            });
            let mut modules = Vec::new();
            let mut me32: MODULEENTRY32W = zeroed();
            me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

            if Module32FirstW(snapshot, &mut me32).is_ok() {
                loop {
                    let module_name = String::from_utf16_lossy(
                        &me32.szModule[..me32
                            .szModule
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(me32.szModule.len())],
                    );

                    modules.push(ModuleInfo {
                        base_address: me32.modBaseAddr as u64,
                        size: me32.modBaseSize,
                        name: module_name.into(),
                    });

                    if !Module32NextW(snapshot, &mut me32).is_ok() {
                        break;
                    }
                }
            }

            Ok(modules)
        }
    }
}
