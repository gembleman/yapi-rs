use crate::YapiError;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};

pub type Result<T> = std::result::Result<T, YapiError>;

pub trait VecExtension {
    fn insert_slice(&mut self, index: usize, slice: &[u8]);
}

impl VecExtension for Vec<u8> {
    fn insert_slice(&mut self, index: usize, slice: &[u8]) {
        let len = slice.len();
        self.resize(self.len() + len, 0);
        self[index..].rotate_right(len);
        self[index..index + len].copy_from_slice(slice);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessHandleWrapper(HANDLE);

impl ProcessHandleWrapper {
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

// HANDLE -> ProcessHandleWrapper
impl From<HANDLE> for ProcessHandleWrapper {
    fn from(handle: HANDLE) -> Self {
        Self(handle)
    }
}

// ProcessHandleWrapper -> HANDLE
impl From<ProcessHandleWrapper> for HANDLE {
    fn from(wrapper: ProcessHandleWrapper) -> Self {
        wrapper.0
    }
}

// &ProcessHandleWrapper -> HANDLE
impl From<&ProcessHandleWrapper> for HANDLE {
    fn from(wrapper: &ProcessHandleWrapper) -> Self {
        wrapper.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub base_address: u64,
    pub size: u32,
    pub name: String,
}

// 대상 프로세스의 64비트 PEB를 읽기 위한 구조체들 (C++ 원본의 _UNICODE_STRING_T,
// _LIST_ENTRY_T, _PEB_T, _PEB_LDR_DATA_T, _LDR_DATA_TABLE_ENTRY_T에 대응)

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString64 {
    pub header: UnicodeStringHeader,
    pub buffer: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union UnicodeStringHeader {
    pub fields: UnicodeStringFields,
    pub dummy: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UnicodeStringFields {
    pub length: u16,
    pub maximum_length: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ListEntry64 {
    pub flink: u64,
    pub blink: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Peb64 {
    pub dummy01: u64,
    pub mutant: u64,
    pub image_base_address: u64,
    pub ldr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PebLdrData64 {
    pub length: u32,
    pub initialized: u32,
    pub ss_handle: u64,
    pub in_load_order_module_list: ListEntry64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LdrDataTableEntry64 {
    pub in_load_order_links: ListEntry64,
    pub in_memory_order_links: ListEntry64,
    pub in_initialization_order_links: ListEntry64,
    pub dll_base: u64,
    pub entry_point: u64,
    pub size_of_image: u32,
    pub __pad0: u32,
    pub full_dll_name: UnicodeString64,
    pub base_dll_name: UnicodeString64,
}

// NtQueryInformationProcess(ProcessBasicInformation)의 64비트 레이아웃
// (C++ 원본의 PROCESS_BASIC_INFORMATION64에 대응)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessBasicInformation64 {
    pub exit_status: NTSTATUS,
    pub reserved0: u32,
    pub peb_base_address: u64,
    pub affinity_mask: u64,
    pub base_priority: u32,
    pub reserved1: u32,
    pub unique_process_id: u64,
    pub inherited_from_unique_process_id: u64,
}

// 실제 Windows 구조체 레이아웃과 일치하는지 컴파일 타임에 검증한다
const _: () = {
    assert!(std::mem::size_of::<UnicodeString64>() == 16);
    assert!(std::mem::size_of::<ListEntry64>() == 16);
    assert!(std::mem::offset_of!(Peb64, ldr) == 0x18);
    assert!(std::mem::offset_of!(PebLdrData64, in_load_order_module_list) == 0x10);
    assert!(std::mem::offset_of!(LdrDataTableEntry64, dll_base) == 0x30);
    assert!(std::mem::offset_of!(LdrDataTableEntry64, size_of_image) == 0x40);
    assert!(std::mem::offset_of!(LdrDataTableEntry64, full_dll_name) == 0x48);
    assert!(std::mem::offset_of!(LdrDataTableEntry64, base_dll_name) == 0x58);
    assert!(std::mem::size_of::<ProcessBasicInformation64>() == 48);
    assert!(std::mem::offset_of!(ProcessBasicInformation64, peb_base_address) == 8);
};

#[derive(Debug, Clone, Copy)]
pub struct YapiArch {
    /// OS 아키텍처(GetNativeSystemInfo 반환값). wow64 프로세스여도 네이티브
    /// OS 비트가 담기므로 프로세스 비트로 읽지 않아야 한다.
    pub host_arch: Architecture,
    /// 대상 프로세스의 아키텍처(wow64면 X86)
    pub target_proc_arch: Architecture,
    /// 호출할 함수의 아키텍처(모듈 PE 헤더 폭 결정에 사용)
    pub func_arch: Architecture,
}

impl YapiArch {
    pub fn new(
        host_arch: Architecture,
        target_proc_arch: Architecture,
        func_arch: Architecture,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            println!("Creating YapiArch with:");
            println!("  Host Process Architecture: {:?}", host_arch);
            println!("  Target Process Architecture: {:?}", target_proc_arch);
            println!("  Function Architecture: {:?}", func_arch);
        }

        Self {
            host_arch,
            target_proc_arch,
            func_arch,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
}
