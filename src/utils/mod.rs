mod memory_reader;

mod process_handle;

#[cfg(target_arch = "x86")]
pub mod x64_gate;

pub use memory_reader::*;

pub use process_handle::*;

use windows::Win32::Foundation::NTSTATUS;

pub fn nt_success(status: NTSTATUS) -> bool {
    status.0 >= 0
}
