use crate::Architecture::*;
use crate::ProcessWriter;
use crate::ShellCodeBuilder;
use crate::error::*;
use crate::types::*;
use crate::utils::*;

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

fn result_from_thread_exit_code<R>(exit_code: u32) -> Result<R>
where
    R: Copy + 'static + Default + std::fmt::Debug,
{
    if std::mem::size_of::<R>() != std::mem::size_of::<u32>() {
        return Err(YapiError::Custom(format!(
            "thread exit code is 4 bytes, but the requested result type is {} bytes",
            std::mem::size_of::<R>()
        )));
    }

    Ok(unsafe { std::mem::transmute_copy(&exit_code) })
}

#[derive(Debug, Clone)]
pub struct YAPICall<R = u64> {
    pub target_process_handle: ProcessHandle,
    pub shell_code_memory: Option<ProcessWriter>,

    #[cfg(target_arch = "x86_64")]
    pub function_address: u64,
    #[cfg(target_arch = "x86")]
    pub function_address: u32,
    // 호스트가 64비트에서는 64비트, 32비트에서는 32비트 함수 주소
    pub dw64_ret: bool,
    pub timeout: Option<Duration>,
    pub yapi_arch: YapiArch,
    shell_code_arg_count: Option<usize>,
    pub _phantom: PhantomData<R>,
}

impl<R> YAPICall<R>
where
    R: Copy + 'static + Default + std::fmt::Debug,
{
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

        // 프로세스 아키텍처 감지 (IsWow64Process 실패는 오류로 처리)
        let target_proc_arch = unsafe {
            let mut is_wow64 = FALSE;
            IsWow64Process(target_process, &mut is_wow64).map_err(YapiError::Windows)?;
            if host_arch == X64 && is_wow64.as_bool() {
                X86
            } else {
                host_arch
            }
        };

        // 함수 아키텍처 결정 - WOW64 함수는 항상 32비트 // is_64bit_func이 true이면 64비트 함수라 간주
        let func_arch = if is_64bit_func { X64 } else { target_proc_arch };

        let yapi_arch = YapiArch::new(host_arch, target_proc_arch, func_arch);
        let target_process_handle = ProcessHandle::new(target_process, yapi_arch)?;

        #[cfg(debug_assertions)]
        println!("Looking for module {} ({:?})", module_name, func_arch);

        // 64비트 함수는 대상 프로세스의 64비트 PEB를 순회해 모듈을 찾는다 (GetModuleHandle64).
        // wow64 대상의 ntdll64 같은 모듈은 32비트 스냅샷 목록에 잡히지 않을 수 있다.
        let module_info = if func_arch == Architecture::X64 {
            target_process_handle.get_module_handle_64(module_name)?
        } else {
            target_process_handle.get_module_handle(module_name)?
        };
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

        // 32비트 호스트에서 함수 주소가 4GB를 넘으면 패닉 대신 오류를 반환한다
        #[cfg(target_arch = "x86")]
        let function_address = u32::try_from(function_address).map_err(|_| {
            YapiError::Custom(format!(
                "function address 0x{function_address:X} exceeds 4GB on a 32-bit host"
            ))
        })?;

        Ok(Self {
            target_process_handle,
            shell_code_memory: None,
            shell_code_arg_count: None,
            #[cfg(target_arch = "x86_64")]
            function_address,
            #[cfg(target_arch = "x86")]
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
            self.init_shell_code(params.len())?;

            // 3. 파라미터 버퍼 준비
            let mut param_buffer = self.prepare_params(params)?;

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
            let result = self.execute_remote_thread(param_buffer.address().as_ptr());
            if result.is_err() {
                param_buffer.dont_free();
            }
            result
        }
    }

    unsafe fn execute_remote_thread(&mut self, param_address: *mut c_void) -> Result<R> {
        #[cfg(target_arch = "x86_64")]
        let shell_code_addr = self.shell_code_memory.as_ref().unwrap().address().as_ptr() as u64;

        // 64비트 함수는 64비트 delegator 쉘코드를 직접 시작 주소로 사용한다.
        // 타깃이 wow64(x86) 프로세스여도 스레드는 지정된 64비트 시작 주소를
        // 64비트 모드로 실행하므로 별도 브릿지가 필요 없다. (C++ 원본도 delegator를 직접 사용)
        let thread_handle = match (self.yapi_arch.func_arch, self.yapi_arch.target_proc_arch) {
            (Architecture::X64, _) => {
                #[cfg(target_arch = "x86")]
                {
                    return Err(YapiError::Custom(
                        "calling a 64-bit function requires a 64-bit injector process".to_string(),
                    ));
                }

                #[cfg(target_arch = "x86_64")]
                unsafe {
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
            }
            // 32비트 함수는 64비트 프로세스에서 실행할 수 없다
            (Architecture::X86, Architecture::X64) => {
                return Err(YapiError::Custom(
                    "cannot call a 32-bit function in a 64-bit process".to_string(),
                ));
            }
            // 32비트 함수: 타깃이 32비트(wow64 포함) 프로세스인 경우
            (Architecture::X86, Architecture::X86) => {
                #[cfg(target_arch = "x86_64")]
                unsafe {
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

                // 32비트 호스트는 RtlCreateUserThread로 스레드를 생성한다
                #[cfg(target_arch = "x86")]
                unsafe {
                    #[cfg(debug_assertions)]
                    println!("host is 32bit func is 32");

                    self.target_process_handle.create_thread(
                        false,
                        None,
                        self.shell_code_memory.as_ref().unwrap().address().as_ptr() as u64,
                        param_address as u64,
                    )?
                }
            }
        };

        let timeout_ms = self
            .timeout
            .map(|d| d.as_millis() as u32)
            .unwrap_or(INFINITE);

        // 성공/실패 모든 경로에서 스레드 핸들이 닫히도록 보장한다
        let _thread_guard = scopeguard::guard(thread_handle, |h| {
            let _ = unsafe { CloseHandle(h) };
        });

        if unsafe { WaitForSingleObject(thread_handle, timeout_ms) } != WAIT_OBJECT_0 {
            // 타임아웃 시 원격 스레드가 아직 메모리를 사용 중일 수 있으므로 해제를 보류한다
            if let Some(sc) = self.shell_code_memory.as_mut() {
                sc.dont_free();
            }
            return Err(YapiError::Thread(ThreadError::TimeoutError {
                ms: timeout_ms,
            }));
        }

        let result = if self.yapi_arch.func_arch == Architecture::X86 || !self.dw64_ret {
            // 32비트 결과 또는 dw64_ret이 false인 경우: 스레드 종료 코드 사용
            #[cfg(debug_assertions)]
            println!("32bit or dw64_ret is false");

            let mut exit_code = 0u32;
            unsafe { GetExitCodeThread(thread_handle, &mut exit_code) }?;
            result_from_thread_exit_code(exit_code)?
        } else {
            // 64비트 결과이고 dw64_ret이 true인 경우: 파라미터 버퍼에서 값을 읽는다
            #[cfg(debug_assertions)]
            println!("64bit and dw64_ret is true");

            let mut result: R = R::default();
            unsafe {
                ReadProcessMemory(
                    self.target_process_handle.as_raw(),
                    param_address,
                    &mut result as *mut R as *mut c_void,
                    std::mem::size_of::<R>(),
                    None,
                )
            }?;
            result
        };

        Ok(result)
    }

    fn init_shell_code(&mut self, arg_count: usize) -> Result<()> {
        // 인자 개수 제한 체크 (u8 변환 절단 전에 검사)
        if arg_count > 6 {
            return Err(YapiError::Custom(
                "Maximum 6 parameters supported".to_string(),
            ));
        }

        // 같은 인자 개수로 이미 생성된 쉘코드가 있다면 재사용
        if self.shell_code_arg_count == Some(arg_count) && self.shell_code_memory.is_some() {
            return Ok(());
        }

        // 새 쉘코드 생성
        let code: Vec<u8> = ShellCodeBuilder::new(self.yapi_arch)
            .make_shell_code(arg_count as u8)?
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
        self.shell_code_arg_count = Some(arg_count);

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
        match self.yapi_arch.func_arch {
            X86 => {
                buffer.extend_from_slice(&(self.function_address as u32).to_le_bytes());
                for &param in params {
                    buffer.extend_from_slice(&(param as u32).to_le_bytes());
                }
            }
            X64 => {
                buffer.extend_from_slice(&(self.dw64_ret as u64).to_le_bytes());
                buffer.extend_from_slice(&self.function_address.to_le_bytes());
                for &param in params {
                    buffer.extend_from_slice(&param.to_le_bytes());
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
                GetProcessId(self.target_process_handle.as_raw()),
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

#[cfg(test)]
mod tests {
    use super::result_from_thread_exit_code;

    #[test]
    fn rejects_result_larger_than_thread_exit_code() {
        let result = result_from_thread_exit_code::<u64>(0x1234_5678);

        assert!(result.is_err());
    }

    #[test]
    fn preserves_four_byte_thread_exit_code() {
        let result = result_from_thread_exit_code::<u32>(0x1234_5678);

        assert_eq!(result.unwrap(), 0x1234_5678);
    }
}
