#![windows_subsystem = "windows"]
use windows::{
    core::*,
    Win32::{Foundation::*, System::Threading::GetCurrentProcessId, UI::WindowsAndMessaging::*},
};

fn main() -> Result<()> {
    // 프로세스 ID를 표시할 문자열 준비
    let pid = unsafe { GetCurrentProcessId() };
    #[cfg(target_arch = "x86")]
    let title = format!("32-bit Test Process (PID: {})", pid);
    #[cfg(target_arch = "x86_64")]
    let title = format!("64-bit Test Process (PID: {})", pid);

    unsafe {
        // 윈도우 클래스 등록
        let instance = HINSTANCE::default();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            lpszClassName: w!("Wow64TestWindow"),
            ..Default::default()
        };

        RegisterClassExW(&wc);

        // 윈도우 생성
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("Wow64TestWindow"),
            &HSTRING::from(title),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            400,
            300,
            None,
            None,
            Some(instance),
            None,
        );

        // 메시지 루프
        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).into() {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    Ok(())
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                // 윈도우가 생성될 때 정적 텍스트 추가
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("STATIC"),
                    w!("This is a 32-bit test process.\r\nUse this window to test WOW64 process injection."),
                    WS_CHILD | WS_VISIBLE,
                    10,
                    10,
                    380,
                    80,
                    Some(hwnd),
                    None,
                    Some(HINSTANCE::default()),
                    None,
                );
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}
