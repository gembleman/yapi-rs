use crate::{MemoryError, YapiError, types::*};
use std::{
    ffi::c_void,
    mem::zeroed,
    sync::LazyLock,
};
use windows::Win32::{
    Foundation::{HANDLE, NTSTATUS},
    System::{Diagnostics::Debug::ReadProcessMemory, LibraryLoader::{GetModuleHandleW, GetProcAddress}},
};
use windows::core::{PCSTR, w};

use super::nt_success;

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

            ReadProcessMemory(
                self.process.as_raw(),
                address as *const c_void,
                &mut buffer as *mut T as *mut c_void,
                size,
                Some(&mut bytes_read),
            )
            .map_err(|e| YapiError::Windows(e))?;

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

            ReadProcessMemory(
                self.process.as_raw(),
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut bytes_read),
            )
            .map_err(YapiError::Windows)?;

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

/// ntdll에서 이름으로 함수를 찾아 지정한 시그니처로 변환한다.
unsafe fn resolve_ntdll_function<F>(name: &[u8]) -> Option<F> {
    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        let proc_addr = GetProcAddress(ntdll, PCSTR(name.as_ptr()))?;
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

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0; // ProcessBasicInformation

/// 대상 프로세스의 64비트 PEB 주소를 얻는다 (C++ 원본의 NtWow64QueryInformationProcess64 사용부에 대응).
///
/// - x64 호스트: NtQueryInformationProcess(ProcessBasicInformation)
/// - wow64 호스트: NtWow64QueryInformationProcess64(ProcessBasicInformation)
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

    let mut pbi: ProcessBasicInformation64 = zeroed();
    let status = unsafe {
        func(
            process,
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

        let status = unsafe { func(process.into(), base_address, buffer, buffer_size, bytes_read) };
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
            ReadProcessMemory(
                process.into(),
                base_address as *const c_void,
                buffer,
                buffer_size as usize,
                Some(&mut bytes_read_32),
            )
            .map_err(YapiError::Windows)?;
        }
        *bytes_read = bytes_read_32 as u64;
    }

    Ok(())
}
