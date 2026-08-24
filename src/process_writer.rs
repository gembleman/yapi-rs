use crate::utils::nt_wow64_write_virtual_memory64;
use crate::{MemoryError, YapiError, types::*};
use std::ffi::c_void;
use std::ptr::NonNull;
use windows::Win32::{
    Foundation::HANDLE,
    System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAllocEx,
        VirtualFreeEx,
    },
};

#[derive(Debug, Clone)]
pub struct ProcessWriter {
    pub process: ProcessHandleWrapper,
    pub address: NonNull<c_void>, // null이 될 수 없음을 보장
    pub size: usize,
    pub should_free: bool, // auto_release 대신 더 명확한 이름 사용
}

impl ProcessWriter {
    pub fn new(process: HANDLE, content: &[u8], protect: PAGE_PROTECTION_FLAGS) -> Result<Self> {
        unsafe {
            let size = content.len();
            let address = VirtualAllocEx(process, None, size, MEM_COMMIT | MEM_RESERVE, protect);

            // NonNull을 사용하여 null check를 한번에 처리
            let address = NonNull::new(address)
                .ok_or_else(|| YapiError::Memory(MemoryError::AllocationFailed))?;

            // x86 호스트에서도 NtWow64WriteVirtualMemory64로 4GB 이상 주소에 쓸 수 있다
            let mut written = 0u64;
            nt_wow64_write_virtual_memory64(
                process.into(),
                address.as_ptr() as u64,
                content.as_ptr() as *const c_void,
                size as u64,
                &mut written,
            )?;

            #[cfg(debug_assertions)]
            println!("Bytes written: {}, Expected: {}", written, size);

            if written != size as u64 {
                // MEM_RELEASE 사용 시 크기는 0이어야 한다
                VirtualFreeEx(process, address.as_ptr(), 0, MEM_RELEASE)?;
                return Err(YapiError::Memory(MemoryError::WriteFailed {
                    address: address.as_ptr() as u64,
                    size,
                }));
            }

            #[cfg(debug_assertions)]
            println!(
                "Allocated {} bytes at 0x{:X}",
                size,
                address.as_ptr() as u64
            );

            Ok(Self {
                process: process.into(),
                address,
                size,
                should_free: true,
            })
        }
    }

    // 메모리 해제 비활성화
    pub fn dont_free(&mut self) {
        self.should_free = false;
    }

    // 메모리 주소 반환 - NonNull을 통해 null이 아님을 보장
    pub fn address(&self) -> NonNull<c_void> {
        self.address
    }
}

impl Drop for ProcessWriter {
    fn drop(&mut self) {
        if self.should_free {
            unsafe {
                // MEM_DECOMMIT은 예약을 남겨 주소 공간이 누수되므로 MEM_RELEASE로 완전 해제한다
                let _ = VirtualFreeEx(
                    self.process.as_raw(),
                    self.address.as_ptr(),
                    0,
                    MEM_RELEASE,
                );
            }
        }
    }
}
