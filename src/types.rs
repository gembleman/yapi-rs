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

#[repr(C)]
pub struct UnicodeString<T> {
    pub header: UnicodeStringHeader<T>,
    pub buffer: T,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union UnicodeStringHeader<T> {
    pub fields: UnicodeStringFields,
    pub dummy: std::mem::ManuallyDrop<T>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UnicodeStringFields {
    pub length: u16,
    pub maximum_length: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ListEntry<T> {
    pub flink: T,
    pub blink: T,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Peb<T> {
    pub dummy01: T,
    pub mutant: T,
    pub image_base_address: T,
    pub ldr: T,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PebLdrData<T> {
    pub length: u32,
    pub initialized: u32,
    pub ss_handle: T,
    pub in_load_order_module_list: ListEntry<T>,
}

#[repr(C)]
pub struct LdrDataTableEntry<T> {
    pub in_load_order_links: ListEntry<T>,
    pub in_memory_order_links: ListEntry<T>,
    pub in_initialization_order_links: ListEntry<T>,
    pub dll_base: T,
    pub entry_point: T,
    pub size_of_image_union: SizeOfImageUnion<T>,
    pub full_dll_name: UnicodeString<T>,
    pub base_dll_name: UnicodeString<T>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SizeOfImageUnion<T> {
    pub size_of_image: u32,
    pub dummy01: std::mem::ManuallyDrop<T>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessBasicInformation32 {
    pub exit_status: NTSTATUS,
    pub peb_base_address: u32,
    pub affinity_mask: u32,
    pub base_priority: u32,
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
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

// Type aliases with layout verification
pub type Peb32 = Peb<u32>;
pub type Peb64 = Peb<u64>;

pub type PebLdrData32 = PebLdrData<u32>;
pub type PebLdrData64 = PebLdrData<u64>;

pub type LdrDataTableEntry32 = LdrDataTableEntry<u32>;
pub type LdrDataTableEntry64 = LdrDataTableEntry<u64>;

#[derive(Debug, Clone, Copy)]
pub struct YapiArch {
    pub host_arch: Architecture,
    pub target_proc_arch: Architecture,
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

    // 타겟 프로세스가 WOW64 프로세스인가?
    pub fn target_proc_is_wow64(&self) -> bool {
        // 호스트 시스템이 64비트여야 함 && 타겟 프로세스가 32비트여야 함
        self.host_arch == Architecture::X64 && self.target_proc_arch == Architecture::X86
    }

    // wow64 브릿지가 필요한가?
    //32비트 타깃 프로세스에서 64비트 함수를 호출하려는 경우
    //64비트 타깃 프로세스에서 32비트 함수를 호출하려는 경우
    // 64비트 호스트에서 32비트 함수를 호출하려는 경우
    // 32비트 호스트에서 64비트 함수를 호출하려는 경우
    pub fn needs_wow64_bridge(&self) -> bool {
        (self.target_proc_arch != self.func_arch) || (self.host_arch != self.func_arch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
}
