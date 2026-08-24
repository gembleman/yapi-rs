#![windows_subsystem = "windows"]
use windows_sys::Win32::{
    Foundation::*,
    System::Threading::GetCurrentProcessId,
    UI::WindowsAndMessaging::*,
};

fn main() {
    // 프로세스 ID를 표시할 문자열 준비
    let pid = unsafe { GetCurrentProcessId() };
    #[cfg(target_arch = "x86")]
    let title = format!("32-bit Test Process (PID: {})", pid);
    #[cfg(target_arch = "x86_64")]
    let title = format!("64-bit Test Process (PID: {})", pid);

    unsafe {
        // 윈도우 클래스 등록
        let instance = std::ptr::null_mut();
        let class_name: [u16; 16] = [
            'W' as u16, 'o' as u16, 'w' as u16, '6' as u16, '4' as u16,
            'T' as u16, 'e' as u16, 's' as u16, 't' as u16, 'W' as u16,
            'i' as u16, 'n' as u16, 'd' as u16, 'o' as u16, 'w' as u16, 0,
        ];
        let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            lpszClassName: class_name.as_ptr(),
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            ..Default::default()
        };

        RegisterClassExW(&wc);

        // 윈도우 생성
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name.as_ptr(),
            title_wide.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            400,
            300,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );

        // 메시지 루프
        let mut message = MSG::default();
        while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                // 윈도우가 생성될 때 정적 텍스트 추가
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    STATIC_CLASS.as_ptr(),
                    TEST_TEXT.as_ptr(),
                    WS_CHILD | WS_VISIBLE,
                    10,
                    10,
                    380,
                    80,
                    hwnd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                );
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

static STATIC_CLASS: &[u16] = &['S' as u16, 'T' as u16, 'A' as u16, 'T' as u16, 'I' as u16, 'C' as u16, 0];
static TEST_TEXT: &[u16] = &[
    'T' as u16, 'h' as u16, 'i' as u16, 's' as u16, ' ' as u16, 'i' as u16, 's' as u16,
    ' ' as u16, 'a' as u16, ' ' as u16, '3' as u16, '2' as u16, '-' as u16, 'b' as u16,
    'i' as u16, 't' as u16, ' ' as u16, 't' as u16, 'e' as u16, 's' as u16, 't' as u16,
    ' ' as u16, 'p' as u16, 'r' as u16, 'o' as u16, 'c' as u16, 'e' as u16, 's' as u16,
    's' as u16, '.' as u16, 0,
];
