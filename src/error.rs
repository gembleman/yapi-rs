use thiserror::Error;
use windows::core;

/// Represents all possible errors that can occur in the YAPI library
#[derive(Debug, Error)]
pub enum YapiError {
    /// Errors from Windows API calls
    #[error("Windows error: {0}")]
    Windows(#[from] core::Error),

    /// Memory-related errors
    #[error(transparent)]
    Memory(MemoryError),

    /// Process-related errors
    #[error(transparent)]
    Process(ProcessError),

    /// Thread-related errors
    #[error(transparent)]
    Thread(ThreadError),

    #[error("Custom error {0}")]
    Custom(String),
}

/// Memory operation specific errors
#[derive(Debug, Error)]
pub enum MemoryError {
    /// Failed to allocate memory in target process
    #[error("Failed to allocate memory")]
    AllocationFailed,

    /// Failed to read from target process memory
    #[error("Failed to read memory at {address:#x}, size: {size}")]
    ReadFailed { address: u64, size: usize },

    /// Failed to write to target process memory
    #[error("Failed to write memory at {address:#x}, size: {size}")]
    WriteFailed { address: u64, size: usize },

    /// Memory protection or query operations failed
    #[error("Memory operation failed: {operation}")]
    OperationFailed { operation: String },
}

/// Process-related errors
#[derive(Debug, Error)]
pub enum ProcessError {
    /// Module not found in target process
    #[error("Module not found: {name}")]
    ModuleNotFound { name: String },

    /// Function not found in module
    #[error("Function not found: {name} in module {module}")]
    FunctionNotFound { name: String, module: String },

    /// Access denied to process
    #[error("Access denied to process {pid}")]
    AccessDenied { pid: u32 },

    #[error("{operation} failed")]
    OperationFailed { operation: &'static str },
}

/// Thread-related errors
#[derive(Debug, Error)]
pub enum ThreadError {
    /// Thread creation failed
    #[error("Failed to create thread: {reason}")]
    CreationFailed { reason: String },

    /// Thread operation timed out
    #[error("Thread operation timed out after {ms}ms")]
    TimeoutError { ms: u32 },
}

// Helper functions for common error cases
impl YapiError {
    pub fn memory_read_failed(address: u64, size: usize) -> Self {
        Self::Memory(MemoryError::ReadFailed { address, size })
    }

    pub fn memory_write_failed(address: u64, size: usize) -> Self {
        Self::Memory(MemoryError::WriteFailed { address, size })
    }

    pub fn module_not_found(name: impl Into<String>) -> Self {
        Self::Process(ProcessError::ModuleNotFound { name: name.into() })
    }

    pub fn function_not_found(name: impl Into<String>, module: impl Into<String>) -> Self {
        Self::Process(ProcessError::FunctionNotFound {
            name: name.into(),
            module: module.into(),
        })
    }

    pub fn thread_timeout(ms: u32) -> Self {
        Self::Thread(ThreadError::TimeoutError { ms })
    }
}

impl From<MemoryError> for YapiError {
    fn from(err: MemoryError) -> Self {
        Self::Memory(err)
    }
}

impl From<ProcessError> for YapiError {
    fn from(err: ProcessError) -> Self {
        Self::Process(err)
    }
}

impl From<ThreadError> for YapiError {
    fn from(err: ThreadError) -> Self {
        Self::Thread(err)
    }
}

//&str 트레이트
impl From<&str> for YapiError {
    fn from(s: &str) -> Self {
        Self::Custom(s.to_string())
    }
}
