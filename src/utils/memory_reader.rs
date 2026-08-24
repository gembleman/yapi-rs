use crate::{MemoryError, YapiError, types::*};
use std::{ffi::c_void, mem::zeroed};
use windows::Win32::{Foundation::NTSTATUS, System::Diagnostics::Debug::ReadProcessMemory};

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

            let status = nt_wow64_read_virtual_memory64(
                self.process,
                address,
                &mut buffer as *mut T as *mut c_void,
                size as u64,
                &mut bytes_read,
            )?;

            if !nt_success(status) || bytes_read != size as u64 {
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

            let status = nt_wow64_read_virtual_memory64(
                self.process,
                address,
                buffer.as_mut_ptr() as *mut c_void,
                size as u64,
                &mut bytes_read,
            )?;

            if !nt_success(status) || bytes_read != size as u64 {
                return Err(YapiError::Memory(MemoryError::ReadFailed { address, size }));
            }
            Ok(buffer
                .into_iter()
                .map(|value| value.assume_init())
                .collect::<Vec<T>>())
        }
    }
}

// #[cfg(target_arch = "x86_64")]
pub unsafe fn nt_wow64_read_virtual_memory64(
    process: ProcessHandleWrapper,
    base_address: u64,
    buffer: *mut c_void,
    buffer_size: u64,
    bytes_read: *mut u64,
) -> Result<NTSTATUS> {
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

        *bytes_read = bytes_read_32 as u64;
    }
    Ok(NTSTATUS(0))
}

// #[cfg(target_arch = "x86")]
// pub unsafe fn nt_wow64_read_virtual_memory64(
//     process: ProcessHandleWrapper,
//     base_address: u64,
//     buffer: *mut c_void,
//     buffer_size: u64,
//     bytes_read: *mut u64,
// ) -> Result<NTSTATUS> {
//     use std::sync::{LazyLock, Mutex};
//     use windows::Win32::System::LibraryLoader::GetProcAddress;

//     static NT_WOW64_READ_VIRTUAL_MEMORY: LazyLock<Mutex<Option<NtWow64ReadVirtualMemory>>> =
//         LazyLock::new(|| Mutex::new(None));

//     let func = {
//         let mut guard = NT_WOW64_READ_VIRTUAL_MEMORY.lock().map_err(|_| {
//             YapiError::Memory(MemoryError::OperationFailed {
//                 operation: "Lock acquisition failed",
//             })
//         })?;

//         if guard.is_none() {
//             let ntdll = super::get_ntdll64()?;
//             let func = GetProcAddress(
//                 ntdll,
//                 windows::core::PCSTR(b"NtWow64ReadVirtualMemory\0".as_ptr()),
//             );
//             *guard = func.map(|f| unsafe { std::mem::transmute(f) });
//         }

//         guard.ok_or(YapiError::Memory(MemoryError::OperationFailed {
//             operation: "Function not found",
//         }))?
//     };

//     Ok(func(process, base_address, buffer, buffer_size, bytes_read))
// }
