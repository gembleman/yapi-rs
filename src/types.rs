use crate::YapiError;
use windows::Win32::Foundation::HANDLE;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
}
