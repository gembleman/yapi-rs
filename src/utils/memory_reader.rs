use crate::{MemoryError, YapiError, types::*};
use std::{
    ffi::c_void,
    mem::zeroed,
    sync::{LazyLock, Mutex},
};
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::{
    Win32::{
        Foundation::{HANDLE, NTSTATUS},
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Threading::{GetCurrentProcess, GetProcessId, OpenProcess, PROCESS_ALL_ACCESS},
        },
    },
    core::w,
};

use super::nt_success;

// wow64의 NtWow64* 함수는 의사 핸들(GetCurrentProcess())을 거부하므로
// 실제 핸들이 필요하다. 프로세스 수명 동안 하나만 열어 두고 재사용한다.
// 실패(None)는 기억하지 않으므로 일시적 실패 후에도 다시 시도한다.
static SELF_REAL_HANDLE: Mutex<Option<usize>> = Mutex::new(None);

/// NtWow64*/게이트 호출용으로 의사 핸들을 실제 핸들로 대체한다.
pub(crate) fn ensure_real_handle(process: HANDLE) -> HANDLE {
    if let Some(real) = self_real_handle_or_none(process) {
        real
    } else {
        process
    }
}

/// process가 현재 프로세스를 가리키면 캐시된 실제 핸들을 반환한다.
fn self_real_handle_or_none(process: HANDLE) -> Option<HANDLE> {
    let is_pseudo = process.is_null() || unsafe { process == GetCurrentProcess() };
    if is_pseudo { self_real_handle() } else { None }
}

/// 현재 프로세스의 실제 핸들(전역 캐시). 아직 열지 않았거나 이전 시도가
/// 실패했으면 OpenProcess를 다시 시도한다.
///
/// 정적 캐시이므로 인스턴스마다 핸들을 새로 열지 않는다(핸들 누수 방지).
pub(crate) fn self_real_handle() -> Option<HANDLE> {
    let mut cached = SELF_REAL_HANDLE.lock().unwrap_or_else(|e| e.into_inner());
    if cached.is_none() {
        *cached = unsafe {
            let pseudo = GetCurrentProcess();
            let pid = GetProcessId(pseudo);
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            (!handle.is_null()).then_some(handle as usize)
        };
    }
    cached.map(|v| v as HANDLE)
}

// Memory reading trait with additional helper method
pub trait MemoryReader {
    fn read<T: Sized>(&self, address: u64) -> Result<T>;
    fn read_array<T: Sized>(&self, address: u64, count: usize) -> Result<Vec<T>>;

    // Helper method to validate read operation
    fn validate_read(bytes_read: usize, expected_size: usize, address: u64) -> Result<()> {
        if bytes_read != expected_size {
            return Err(YapiError::Memory(MemoryError::ReadFailed {
                address,
                size: expected_size,
            }));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessReader {
    Reader32(Process32Reader),
    Reader64(Process64Reader),
}

impl MemoryReader for ProcessReader {
    #[inline]
    fn read<T: Sized>(&self, address: u64) -> Result<T> {
        match self {
            ProcessReader::Reader32(reader) => reader.read(address),
            ProcessReader::Reader64(reader) => reader.read(address),
        }
    }

    #[inline]
    fn read_array<T: Sized>(&self, address: u64, count: usize) -> Result<Vec<T>> {
        match self {
            ProcessReader::Reader32(reader) => reader.read_array(address, count),
            ProcessReader::Reader64(reader) => reader.read_array(address, count),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Process32Reader {
    pub process: ProcessHandleWrapper,
}

impl MemoryReader for Process32Reader {
    fn read<T: Sized>(&self, address: u64) -> Result<T> {
        unsafe {
            if address > u32::MAX as u64 {
                return Err(YapiError::Memory(MemoryError::ReadFailed {
                    address,
                    size: std::mem::size_of::<T>(),
                }));
            }

            let mut buffer: T = zeroed();
            let size = std::mem::size_of::<T>();
            let mut bytes_read = 0;

            if ReadProcessMemory(
                self.process.as_raw(),
                address as *const c_void,
                &mut buffer as *mut T as *mut c_void,
                size,
                &mut bytes_read,
            ) == 0
            {
                return Err(YapiError::Memory(MemoryError::ReadFailed { address, size }));
            }

            Self::validate_read(bytes_read, size, address)?;
            Ok(buffer)
        }
    }

    fn read_array<T: Sized>(&self, address: u64, count: usize) -> Result<Vec<T>> {
        unsafe {
            if address > u32::MAX as u64 {
                return Err(YapiError::Memory(MemoryError::ReadFailed {
                    address,
                    size: std::mem::size_of::<T>() * count,
                }));
            }

            let mut buffer: Vec<std::mem::MaybeUninit<T>> = Vec::with_capacity(count);
            buffer.resize_with(count, std::mem::MaybeUninit::uninit);
            let size = std::mem::size_of::<T>() * count;
            let mut bytes_read = 0;

            if ReadProcessMemory(
                self.process.as_raw(),
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            ) == 0
            {
                return Err(YapiError::Memory(MemoryError::ReadFailed { address, size }));
            }

            Self::validate_read(bytes_read, size, address)?;
            Ok(buffer
                .into_iter()
                .map(|value| value.assume_init())
                .collect::<Vec<T>>())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Process64Reader {
    pub process: ProcessHandleWrapper,
}

impl MemoryReader for Process64Reader {
    fn read<T: Sized>(&self, address: u64) -> Result<T> {
        unsafe {
            let mut buffer: T = zeroed();
            let size = std::mem::size_of::<T>();
            let mut bytes_read = 0u64;

            nt_wow64_read_virtual_memory64(
                self.process,
                address,
                &mut buffer as *mut T as *mut c_void,
                size as u64,
                &mut bytes_read,
            )?;

            if bytes_read != size as u64 {
                return Err(YapiError::Memory(MemoryError::ReadFailed { address, size }));
            }
            Ok(buffer)
        }
    }

    fn read_array<T: Sized>(&self, address: u64, count: usize) -> Result<Vec<T>> {
        unsafe {
            let mut buffer: Vec<std::mem::MaybeUninit<T>> = Vec::with_capacity(count);
            buffer.resize_with(count, std::mem::MaybeUninit::uninit);
            let size = std::mem::size_of::<T>() * count;
            let mut bytes_read = 0u64;

            nt_wow64_read_virtual_memory64(
                self.process,
                address,
                buffer.as_mut_ptr() as *mut c_void,
                size as u64,
                &mut bytes_read,
            )?;

            if bytes_read != size as u64 {
                return Err(YapiError::Memory(MemoryError::ReadFailed { address, size }));
            }
            Ok(buffer
                .into_iter()
                .map(|value| value.assume_init())
                .collect::<Vec<T>>())
        }
    }
}

// ntdll 동적 해석 ---------------------------------------------------------------

type NtQueryProcessInformationFn = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS;

/// 4GB를 넘는 주소 읽기용 함수 시그니처 (x86 호스트 빌드 전용).
#[cfg(target_arch = "x86")]
type NtWow64ReadVirtualMemory64Fn = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: u64,
    buffer: *mut c_void,
    buffer_size: u64,
    bytes_read: *mut u64,
) -> NTSTATUS;

/// 4GB를 넘는 주소 쓰기용 함수 시그니처 (x86 호스트 빌드 전용).
#[cfg(target_arch = "x86")]
type NtWow64WriteVirtualMemory64Fn = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: u64,
    buffer: *const c_void,
    buffer_size: u64,
    bytes_written: *mut u64,
) -> NTSTATUS;

/// ntdll에서 이름으로 함수를 찾아 지정한 시그니처로 변환한다.
unsafe fn resolve_ntdll_function<F>(name: &[u8]) -> Option<F> {
    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll"));
        if ntdll.is_null() {
            return None;
        }
        let proc_addr = GetProcAddress(ntdll, name.as_ptr())?;
        Some(std::mem::transmute_copy(&proc_addr))
    }
}

/// ProcessBasicInformation 조회용 함수.
/// - x64 호스트 빌드: NtQueryInformationProcess
/// - x86 호스트 빌드(64비트 OS의 wow64 프로세스): NtWow64QueryInformationProcess64
#[cfg(target_arch = "x86_64")]
static NT_QUERY_PROCESS_INFO_64: LazyLock<Option<NtQueryProcessInformationFn>> =
    LazyLock::new(|| unsafe { resolve_ntdll_function(b"NtQueryInformationProcess\0") });

#[cfg(target_arch = "x86")]
static NT_QUERY_PROCESS_INFO_64: LazyLock<Option<NtQueryProcessInformationFn>> =
    LazyLock::new(|| unsafe { resolve_ntdll_function(b"NtWow64QueryInformationProcess64\0") });

/// 4GB를 넘는 주소 읽기용 함수 (x86 호스트 빌드에서만 필요).
#[cfg(target_arch = "x86")]
static NT_WOW64_READ_VIRTUAL_MEMORY_64: LazyLock<Option<NtWow64ReadVirtualMemory64Fn>> =
    LazyLock::new(|| unsafe { resolve_ntdll_function(b"NtWow64ReadVirtualMemory64\0") });

/// 4GB를 넘는 주소 쓰기용 함수 (x86 호스트 빌드에서만 필요).
#[cfg(target_arch = "x86")]
static NT_WOW64_WRITE_VIRTUAL_MEMORY_64: LazyLock<Option<NtWow64WriteVirtualMemory64Fn>> =
    LazyLock::new(|| unsafe { resolve_ntdll_function(b"NtWow64WriteVirtualMemory64\0") });

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0; // ProcessBasicInformation

/// 대상 프로세스의 64비트 PEB 주소를 얻는다 (C++ 원본의 NtWow64QueryInformationProcess64 사용부에 대응).
///
/// - x64 호스트: NtQueryInformationProcess(ProcessBasicInformation)
/// - wow64 호스트: NtWow64QueryInformationProcess64(ProcessBasicInformation)
///
/// # Safety
///
/// `process`는 PROCESS_QUERY_INFORMATION 권한을 가진 유효한 프로세스 핸들이어야 한다.
pub unsafe fn nt_wow64_query_information_process64(
    process: HANDLE,
) -> Result<ProcessBasicInformation64> {
    let func = *NT_QUERY_PROCESS_INFO_64;
    let Some(func) = func else {
        return Err(YapiError::Custom(
            "NtQueryInformationProcess/NtWow64QueryInformationProcess64 is not available"
                .to_string(),
        ));
    };

    let mut pbi: ProcessBasicInformation64 = unsafe { zeroed() };
    let status = unsafe {
        func(
            ensure_real_handle(process),
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut ProcessBasicInformation64 as *mut c_void,
            std::mem::size_of::<ProcessBasicInformation64>() as u32,
            std::ptr::null_mut(),
        )
    };

    if !nt_success(status) {
        return Err(YapiError::Custom(format!(
            "querying 64-bit process basic information failed with NTSTATUS {status:?}"
        )));
    }
    Ok(pbi)
}

/// 대상 프로세스의 임의 64비트 주소를 읽는다 (C++ 원본의 NtWow64ReadVirtualMemory64에 대응).
///
/// - x64 호스트: ReadProcessMemory로 충분하다
/// - wow64 호스트: ntdll의 NtWow64ReadVirtualMemory64로 4GB 이상 주소도 읽는다
///
/// # Safety
///
/// `process`는 PROCESS_VM_READ 권한을 가진 핸들이어야 하고, `buffer`는
/// `buffer_size`바이트 이상 쓸 수 있는 유효한 메모리여야 한다.
pub unsafe fn nt_wow64_read_virtual_memory64(
    process: ProcessHandleWrapper,
    base_address: u64,
    buffer: *mut c_void,
    buffer_size: u64,
    bytes_read: *mut u64,
) -> Result<()> {
    #[cfg(target_arch = "x86")]
    {
        let func = *NT_WOW64_READ_VIRTUAL_MEMORY_64;
        let Some(func) = func else {
            return Err(YapiError::Custom(
                "NtWow64ReadVirtualMemory64 is not available (requires a 64-bit OS)".to_string(),
            ));
        };

        let process = ensure_real_handle(process.into());
        let status = unsafe { func(process, base_address, buffer, buffer_size, bytes_read) };
        if !nt_success(status) {
            return Err(YapiError::Memory(MemoryError::ReadFailed {
                address: base_address,
                size: buffer_size as usize,
            }));
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        let mut bytes_read_32 = 0usize;
        unsafe {
            if ReadProcessMemory(
                process.into(),
                base_address as *const c_void,
                buffer,
                buffer_size as usize,
                &mut bytes_read_32,
            ) == 0
            {
                return Err(YapiError::Memory(MemoryError::ReadFailed {
                    address: base_address,
                    size: buffer_size as usize,
                }));
            }
            *bytes_read = bytes_read_32 as u64;
        }
    }

    Ok(())
}

/// 대상 프로세스의 임의 64비트 주소에 쓴다 (C++ 원본의 WriteProcessMemory64/NtWow64WriteVirtualMemory64 대응).
///
/// - x64 호스트: WriteProcessMemory로 충분하다
/// - wow64 호스트: ntdll의 NtWow64WriteVirtualMemory64로 4GB 이상 주소에도 쓴다
///   (헤븐즈 게이트 없이 호출 가능한 실제 export다)
///
/// # Safety
///
/// `process`는 PROCESS_VM_WRITE 권한을 가진 핸들이어야 하고, `buffer`는
/// `buffer_size`바이트 이상 읽을 수 있는 유효한 메모리여야 한다.
pub unsafe fn nt_wow64_write_virtual_memory64(
    process: ProcessHandleWrapper,
    base_address: u64,
    buffer: *const c_void,
    buffer_size: u64,
    bytes_written: *mut u64,
) -> Result<()> {
    #[cfg(target_arch = "x86")]
    {
        let func = *NT_WOW64_WRITE_VIRTUAL_MEMORY_64;
        let Some(func) = func else {
            return Err(YapiError::Custom(
                "NtWow64WriteVirtualMemory64 is not available (requires a 64-bit OS)".to_string(),
            ));
        };

        let process = ensure_real_handle(process.into());
        let status = unsafe { func(process, base_address, buffer, buffer_size, bytes_written) };
        if !nt_success(status) {
            return Err(YapiError::Memory(MemoryError::WriteFailed {
                address: base_address,
                size: buffer_size as usize,
            }));
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        let mut bytes_written_32 = 0usize;
        unsafe {
            if WriteProcessMemory(
                process.into(),
                base_address as *const c_void,
                buffer,
                buffer_size as usize,
                &mut bytes_written_32,
            ) == 0
            {
                return Err(YapiError::Memory(MemoryError::WriteFailed {
                    address: base_address,
                    size: buffer_size as usize,
                }));
            }
            *bytes_written = bytes_written_32 as u64;
        }
    }

    Ok(())
}
