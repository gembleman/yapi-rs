//! 헤븐즈 게이트 (C++ 원본의 x64Call 포팅)
//!
//! wow64 프로세스(32비트 호스트 빌드)에서 64비트 모드로 전환해
//! 대상의 64비트 네이티브 API를 직접 호출한다.
//! 원리: far retf(CS=0x33)로 롱 모드에 진입 → 함수 호출 → CS=0x23으로 복귀.
//! http://blog.rewolf.pl/blog/?p=102 참조.

#![cfg(target_arch = "x86")]

use crate::{MemoryError, Result, YapiError};
use std::sync::{LazyLock, Mutex};
use windows_sys::Win32::{
    Foundation::{HANDLE, NTSTATUS},
    System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
};

/// x64Call 스텁 (cdecl 가변인자: func, argCount, args...)
/// 원본 yapi.hpp의 __emit 바이트열과 동일하다.
const X64_CALL: &[u8] = &[
    0x55, 0x8b, 0xec, 0x8b, 0x4d, 0x10, 0x8d, 0x55, 0x14, 0x83, 0xec, 0x40, 0x53, 0x56, 0x57, 0x85,
    0xc9, 0x7e, 0x15, 0x8b, 0x45, 0x14, 0x8d, 0x55, 0x1c, 0x49, 0x89, 0x45, 0xf0, 0x8b, 0x45, 0x18,
    0x89, 0x4d, 0x10, 0x89, 0x45, 0xf4, 0xeb, 0x08, 0x0f, 0x57, 0xc0, 0x66, 0x0f, 0x13, 0x45, 0xf0,
    0x85, 0xc9, 0x7e, 0x15, 0x49, 0x83, 0xc2, 0x08, 0x89, 0x4d, 0x10, 0x8b, 0x42, 0xf8, 0x89, 0x45,
    0xe8, 0x8b, 0x42, 0xfc, 0x89, 0x45, 0xec, 0xeb, 0x08, 0x0f, 0x57, 0xc0, 0x66, 0x0f, 0x13, 0x45,
    0xe8, 0x85, 0xc9, 0x7e, 0x15, 0x49, 0x83, 0xc2, 0x08, 0x89, 0x4d, 0x10, 0x8b, 0x42, 0xf8, 0x89,
    0x45, 0xe0, 0x8b, 0x42, 0xfc, 0x89, 0x45, 0xe4, 0xeb, 0x08, 0x0f, 0x57, 0xc0, 0x66, 0x0f, 0x13,
    0x45, 0xe0, 0x85, 0xc9, 0x7e, 0x15, 0x49, 0x83, 0xc2, 0x08, 0x89, 0x4d, 0x10, 0x8b, 0x42, 0xf8,
    0x89, 0x45, 0xd8, 0x8b, 0x42, 0xfc, 0x89, 0x45, 0xdc, 0xeb, 0x08, 0x0f, 0x57, 0xc0, 0x66, 0x0f,
    0x13, 0x45, 0xd8, 0x8b, 0xc2, 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x99, 0x0f, 0x57, 0xc0,
    0x89, 0x45, 0xc0, 0x8b, 0xc1, 0x89, 0x55, 0xc4, 0x99, 0x66, 0x0f, 0x13, 0x45, 0xc8, 0x89, 0x45,
    0xd0, 0x89, 0x55, 0xd4, 0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x8c, 0x65, 0xf8, 0xb8,
    0x2b, 0x00, 0x00, 0x00, 0x66, 0x8e, 0xe0, 0x89, 0x65, 0xfc, 0x83, 0xe4, 0xf0, 0x6a, 0x33, 0xe8,
    0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xcb, 0x48, 0x8b, 0x4d, 0xf0, 0x48, 0x8b, 0x55,
    0xe8, 0xff, 0x75, 0xe0, 0x49, 0x58, 0xff, 0x75, 0xd8, 0x49, 0x59, 0x48, 0x8b, 0x45, 0xd0, 0xa8,
    0x01, 0x75, 0x03, 0x83, 0xec, 0x08, 0x57, 0x48, 0x8b, 0x7d, 0xc0, 0x48, 0x85, 0xc0, 0x74, 0x16,
    0x48, 0x8d, 0x7c, 0xc7, 0xf8, 0x48, 0x85, 0xc0, 0x74, 0x0c, 0xff, 0x37, 0x48, 0x83, 0xef, 0x08,
    0x48, 0x83, 0xe8, 0x01, 0xeb, 0xef, 0x48, 0x83, 0xec, 0x20, 0xff, 0x55, 0x08, 0x48, 0x8b, 0x4d,
    0xd0, 0x48, 0x8d, 0x64, 0xcc, 0x20, 0x5f, 0x48, 0x89, 0x45, 0xc8, 0xe8, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x0d, 0xcb, 0x66, 0x8c, 0xd8,
    0x66, 0x8e, 0xd0, 0x8b, 0x65, 0xfc, 0x66, 0x8b, 0x45, 0xf8, 0x66, 0x8e, 0xe0, 0x8b, 0x45, 0xc8,
    0x8b, 0x55, 0xcc, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3,
];

/// 게이트 시그니처: x64Call(DWORD64 func, int argCount, ...)과 동일한 cdecl 가변인자.
pub type X64GateFn = unsafe extern "C" fn(func: u64, arg_count: i32, ...) -> u64;

/// 스텁을 실행 가능한 메모리에 복사한다 (.rdata는 실행 불가하므로).
unsafe fn build_gate() -> Result<X64GateFn> {
    unsafe {
        let mem = VirtualAlloc(
            std::ptr::null(),
            X64_CALL.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        let Some(mem) = std::ptr::NonNull::new(mem) else {
            return Err(YapiError::Memory(MemoryError::AllocationFailed));
        };
        std::ptr::copy_nonoverlapping(X64_CALL.as_ptr(), mem.as_ptr() as *mut u8, X64_CALL.len());
        Ok(std::mem::transmute_copy(&mem))
    }
}

/// 게이트 스텁 함수 포인터 캐시. 할당 실패(None)는 기억하지 않으므로
/// 다음 호출에서 다시 시도한다 (일시적 실패 복구).
static GATE: Mutex<Option<X64GateFn>> = Mutex::new(None);

fn cached_gate() -> Result<X64GateFn> {
    let mut cached = GATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(g) = *cached {
        return Ok(g);
    }
    let built = unsafe { build_gate() }?;
    *cached = Some(built);
    Ok(built)
}

/// 현재(wow64) 프로세스의 64비트 ntdll에서 export 주소를 찾는다.
fn resolve_local_ntdll_64_export(name: &[u8]) -> Option<u64> {
    // NtWow64*와 달리 게이트 경로는 의사 핸들을 받지 않으므로 실제 핸들을 연다
    let pid = unsafe {
        windows_sys::Win32::System::Threading::GetProcessId(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
        )
    };
    let handle = unsafe {
        windows_sys::Win32::System::Threading::OpenProcess(
            windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return None;
    }

    let arch = crate::YapiArch::new(
        crate::Architecture::X64,
        crate::Architecture::X64,
        crate::Architecture::X64,
    );
    let ph = crate::ProcessHandle::new(handle, arch).ok()?;
    let ntdll_base = ph.get_ntdll_64().ok()?;
    ph.get_proc_address(ntdll_base, core::str::from_utf8(name).ok()?)
        .ok()
}

/// 64비트 ntdll의 RtlCreateUserThread 주소.
static RTL_CREATE_USER_THREAD_64: LazyLock<Option<u64>> =
    LazyLock::new(|| resolve_local_ntdll_64_export(b"RtlCreateUserThread"));

/// 게이트로 64비트 함수를 직접 호출한다 (C++ 원본의 X64Call 클래스 대응).
/// 인자는 최대 10개(RtlCreateUserThread 기준)까지 지원한다.
///
/// # Safety
///
/// `func`은 현재(wow64) 프로세스에서 호출 가능한 64비트 함수 주소여야 하고,
/// `args`는 해당 함수의 x64 호출 규약과 정확히 일치해야 한다.
pub unsafe fn x64_call(func: u64, args: &[u64]) -> Result<u64> {
    // 패닉 대신 오류로 보고한다 (라이브러리 전반의 Result 원칙)
    if args.len() > 10 {
        return Err(YapiError::Custom(
            "heaven's gate supports up to 10 arguments".to_string(),
        ));
    }

    let gate = cached_gate()?;

    // 가변인자 호출: 인자 개수별 분기 (Rust는 슬라이스를 varargs로 흩을 수 없다)
    unsafe {
        match args.len() {
            0 => Ok(gate(func, 0)),
            1 => Ok(gate(func, 1, args[0])),
            2 => Ok(gate(func, 2, args[0], args[1])),
            3 => Ok(gate(func, 3, args[0], args[1], args[2])),
            4 => Ok(gate(func, 4, args[0], args[1], args[2], args[3])),
            5 => Ok(gate(func, 5, args[0], args[1], args[2], args[3], args[4])),
            6 => Ok(gate(
                func, 6, args[0], args[1], args[2], args[3], args[4], args[5],
            )),
            7 => Ok(gate(
                func, 7, args[0], args[1], args[2], args[3], args[4], args[5], args[6],
            )),
            8 => Ok(gate(
                func, 8, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
            )),
            9 => Ok(gate(
                func, 9, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
                args[8],
            )),
            10 => Ok(gate(
                func, 10, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
                args[8], args[9],
            )),
            _ => unreachable!(),
        }
    }
}

/// 게이트로 64비트 ntdll의 RtlCreateUserThread를 호출해
/// 지정 주소에서 64비트 모드로 시작하는 스레드를 생성한다 (C++ 원본의 CreateRemoteThread64 대응).
///
/// 성공 시 대상 프로세스 관점의 스레드 핸들(HANDLE, 32비트 범위)을 반환한다.
///
/// # Safety
///
/// `process`는 대상 프로세스의 유효한 핸들이어야 하고, `start_address`는
/// 대상에서 64비트 모드로 실행 가능한 코드여야 한다. 스레드는 즉시 실행된다.
pub unsafe fn create_remote_thread_64(
    process: HANDLE,
    start_address: u64,
    parameter: u64,
) -> Result<HANDLE> {
    unsafe { create_remote_thread_64_suspended(process, false, start_address, parameter) }
}

/// `suspended = true`면 중지된 상태로 생성한다.
///
/// # Safety
///
/// `create_remote_thread_64`와 동일하다. `suspended = true`여도 반환된 핸들로
/// 스레드를 재개하면 `start_address`의 코드가 실행된다.
pub unsafe fn create_remote_thread_64_suspended(
    process: HANDLE,
    suspended: bool,
    start_address: u64,
    parameter: u64,
) -> Result<HANDLE> {
    let func = *RTL_CREATE_USER_THREAD_64;
    let Some(func) = func else {
        return Err(YapiError::Custom(
            "RtlCreateUserThread not found in 64-bit ntdll".to_string(),
        ));
    };

    let mut thread_handle: u64 = 0;
    let mut stack_size: u64 = 0;
    // 64비트 세계에서는 32비트 의사 핸들(-1)이 유효하지 않으므로 실제 핸들로 대체한다
    let process = super::memory_reader::ensure_real_handle(process);

    // RtlCreateUserThread(Process, SecurityDescriptor=NULL, Suspended, ZeroBits=0,
    //                     MaxStack=&stack_size, CommitStack=&stack_size, StartAddress, Parameter,
    //                     ThreadHandle=&out, ClientId=NULL)
    // 주의: 스택 크기 포인터는 NULL이 아니라 유효한 값을 넘겨야 한다 (C++ 원본과 동일).
    let status_raw = unsafe {
        x64_call(
            func,
            &[
                process as usize as u64, // Process
                0,                       // SecurityDescriptor (NULL)
                suspended as u64,        // Suspended (BOOLEAN)
                0,                       // ZeroBits
                &mut stack_size as *mut u64 as usize as u64,
                &mut stack_size as *mut u64 as usize as u64,
                start_address,
                parameter,
                &mut thread_handle as *mut u64 as usize as u64,
                0, // ClientId (NULL)
            ],
        )?
    } as u32;

    let status = status_raw as NTSTATUS;
    if !super::nt_success(status) || thread_handle == 0 {
        return Err(YapiError::Thread(crate::ThreadError::CreationFailed {
            reason: format!("RtlCreateUserThread(64) failed with status {:#x}", status),
        }));
    }

    Ok(thread_handle as usize as HANDLE)
}
