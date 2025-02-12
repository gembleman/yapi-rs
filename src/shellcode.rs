use crate::{Architecture::*, VecExtension, YapiArch};

// Constants for x64 register loading patterns
pub const LOAD_RCX: [u8; 4] = [0x48, 0x8b, 0x49, 0x10]; // First param: mov rcx, [rbx+0x10]
pub const LOAD_RDX_ALT: [u8; 4] = [0x48, 0x8b, 0x51, 0x18]; // Second param: mov rdx, [rbx+0x18]
pub const LOAD_RDX: [u8; 4] = [0x48, 0x8b, 0x53, 0x18]; // Second param: mov rdx, [rbx+0x18]
pub const LOAD_R8: [u8; 4] = [0x4c, 0x8b, 0x43, 0x20]; // Third param: mov r8, [rbx+0x20]
pub const LOAD_R9: [u8; 4] = [0x4c, 0x8b, 0x4b, 0x28]; // Fourth param: mov r9, [rbx+0x28]
pub const LOAD_RAX: [u8; 4] = [0x48, 0x8b, 0x43, 0x08]; // Function address: mov rax, [rbx+0x8]
pub const LOAD_R10: [u8; 4] = [0x4c, 0x8b, 0x53, 0x30]; // Fifth param: mov r10, [rbx+0x30]
pub const LOAD_R11: [u8; 4] = [0x4c, 0x8b, 0x5b, 0x30]; // Sixth param: mov r11, [rbx+0x30]
pub const STORE_STACK_PARAM: [u8; 5] = [0x4c, 0x89, 0x54, 0x24, 0x20]; // Stack param: mov [rsp+0x20], r10
pub const STORE_STACK_PARAM_R11: [u8; 5] = [0x4c, 0x89, 0x5c, 0x24, 0x20]; // Stack param: mov [rsp+0x20], r11

// Constants for x86 patterns and offsets
pub const X86_PATTERNS: [[u8; 7]; 3] = [
    [0x8b, 0x48, 0xcc, 0x51, 0x8b, 0x55, 0x08], // Pattern 1
    [0x8b, 0x42, 0xcc, 0x50, 0x8b, 0x4d, 0x08], // Pattern 2
    [0x8b, 0x51, 0xcc, 0x52, 0x8b, 0x45, 0x08], // Pattern 3
];

pub const X86_OFFSETS: [u8; 3] = [0x08, 0x02, 0x11]; // ECX, EAX, EDX offsets

// Templates and bridges are kept as is due to their specific binary nature
pub const K_TMPL_X64: &[u8] = &[
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0x48, 0x85, 0xc9, 0x74, 0x1d, 0x48, 0x83,
    0x39, 0x00, 0x48, 0x8b, 0x41, 0x08, 0x74, 0x0b, 0xff, 0xd0, 0x48, 0x89, 0x03, 0x48, 0x83, 0xc4,
    0x20, 0x5b, 0xc3, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0x48, 0xff, 0xe0, 0x33, 0xc0, 0x48, 0x83, 0xc4,
    0x20, 0x5b, 0xc3,
]; // Same content as before

pub const K_TMPL_X86: &[u8] = &[
    0x55, 0x8b, 0xec, 0x51, 0x83, 0x7d, 0x08, 0x00, 0x74, 0x0c, 0x8b, 0x45, 0x08, 0x8b, 0x08, 0xff,
    0xd0, 0x89, 0x45, 0xfc, 0xeb, 0x07, 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x45, 0xfc,
    0x8b, 0xe5, 0x5d, 0xc3,
];

#[derive(Debug, Clone)]
pub struct ShellCodeBuilder {
    shell_code: Vec<u8>,
    yapi_arch: YapiArch,
}

impl ShellCodeBuilder {
    pub fn new(yapi_arch: YapiArch) -> Self {
        let template = match yapi_arch.func_arch {
            X64 => K_TMPL_X64.to_vec(),

            X86 => K_TMPL_X86.to_vec(),
        };

        Self {
            shell_code: template,
            yapi_arch,
        }
    }

    fn make_x64_shell_code(&mut self, cnt: u8) {
        if cnt == 0 {
            return;
        }

        // Adjust jump distance
        self.shell_code[13] += if cnt <= 4 {
            cnt * 4
        } else {
            (cnt - 4) * 9 + 16
        };
        if cnt >= 1 {
            self.shell_code[16] = 0x3b;
        }

        match cnt {
            1..=2 => {
                if cnt >= 1 {
                    self.shell_code.insert_slice(22, &LOAD_RCX);
                }
                if cnt >= 2 {
                    self.shell_code.insert_slice(22, &LOAD_RDX_ALT);
                }
            }
            3..=6 => {
                self.shell_code[20] = 0x49;
                self.shell_code[21] = 0x10;
                self.shell_code.insert_slice(22, &LOAD_RDX);
                self.shell_code.insert_slice(22, &LOAD_R8);
                self.shell_code.insert_slice(22, &LOAD_RAX);

                if cnt >= 4 {
                    self.shell_code.insert_slice(26, &LOAD_R9);
                }
                if cnt >= 5 {
                    self.shell_code.insert_slice(18, &LOAD_R10);
                    self.shell_code.insert_slice(42, &STORE_STACK_PARAM);
                }
                if cnt >= 6 {
                    self.shell_code[21] = 0x38;
                    self.shell_code.insert_slice(22, &LOAD_R11);
                    self.shell_code[50] = 0x28;
                    self.shell_code.insert_slice(51, &STORE_STACK_PARAM_R11);
                }
            }
            _ => {}
        }
    }

    fn make_x86_shell_code(&mut self, cnt: u8) {
        // 오버플로우 체크 추가
        if cnt > 36 {
            // 255/7 ≈ 36
            return;
        }

        self.shell_code[9] += cnt * 7;

        self.shell_code[16] += (((1 - cnt as i8) % 3 + 3) % 3) as u8;

        let mut pos = 13;
        for i in 0..cnt {
            let mut pattern = X86_PATTERNS[i as usize % 3];
            pattern[2] = ((cnt - i) << 2) as u8;
            self.shell_code.insert_slice(pos, &pattern);
            pos += 7;
        }

        if pos + 1 < self.shell_code.len() {
            self.shell_code[pos + 1] = X86_OFFSETS[cnt as usize % 3];
        }
    }

    pub fn make_shell_code(&mut self, cnt: u8) -> &mut Self {
        match self.yapi_arch.func_arch {
            X64 => self.make_x64_shell_code(cnt),
            X86 => self.make_x86_shell_code(cnt),
        }
        self
    }

    pub fn build(&self) -> Vec<u8> {
        #[cfg(debug_assertions)]
        self.debug_validate();

        self.shell_code.clone()
    }

    #[cfg(debug_assertions)]
    fn debug_validate(&self) {
        if self.shell_code.is_empty()
            || (self.yapi_arch.host_arch == X64 && self.shell_code.len() < K_TMPL_X64.len())
            || (self.yapi_arch.host_arch == X86 && self.shell_code.len() < K_TMPL_X86.len())
        {
            println!("!!!!!!!!!Warning: Invalid shellcode generated!!!!!");
        }
        println!("Building shellcode: {} bytes", self.shell_code.len());
    }

    pub fn dump_code(&self) -> String {
        self.shell_code
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
