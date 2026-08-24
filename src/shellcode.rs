use crate::{Architecture::*, Result, VecExtension, YapiArch, YapiError};

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

    pub fn make_shell_code(&mut self, cnt: u8) -> Result<&mut Self> {
        match self.yapi_arch.func_arch {
            X64 => {
                if cnt > 6 {
                    return Err(YapiError::Custom(
                        "Maximum 6 parameters supported for 64-bit functions".to_string(),
                    ));
                }
                self.make_x64_shell_code(cnt);
            }
            X86 => {
                // je(rel8) 거리(바이트 9 = 0x0c + cnt*7)가 부호 있는 1바이트 범위(+127)를
                // 넘지 않아야 한다. 원본 C++은 이 범위를 넘으면 조용히 손상되므로
                // 명시적 오류로 바꾼다 (0x0c + cnt*7 <= 127 → cnt <= 16).
                if cnt > 16 {
                    return Err(YapiError::Custom(
                        "Maximum 16 parameters supported for 32-bit functions".to_string(),
                    ));
                }
                self.make_x86_shell_code(cnt);
            }
        }
        Ok(self)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Architecture;

    fn builder(func_arch: Architecture) -> ShellCodeBuilder {
        ShellCodeBuilder::new(YapiArch {
            host_arch: Architecture::X64,
            target_proc_arch: func_arch,
            func_arch,
        })
    }

    #[test]
    fn rejects_more_than_six_args_for_x64() {
        assert!(builder(Architecture::X64).make_shell_code(7).is_err());
    }

    #[test]
    fn rejects_too_many_args_for_x86() {
        assert!(builder(Architecture::X86).make_shell_code(17).is_err());
        assert!(builder(Architecture::X86).make_shell_code(37).is_err());
    }

    #[test]
    fn accepts_sixteen_args_for_x86() {
        // je(rel8) 거리 한계 내 최대 인자 수
        let code = builder(Architecture::X86)
            .make_shell_code(16)
            .unwrap()
            .build();
        assert_eq!(code.len(), 36 + 16 * 7);
    }

    #[test]
    fn generates_expected_lengths_for_x64() {
        // 기본 51바이트 + 인자 개수에 따른 삽입 크기
        let expected = [51, 55, 59, 63, 67, 76, 85];
        for (cnt, len) in expected.iter().enumerate() {
            let code = builder(Architecture::X64)
                .make_shell_code(cnt as u8)
                .unwrap()
                .build();
            assert_eq!(code.len(), *len, "cnt={cnt}");
        }
    }

    #[test]
    fn generates_expected_length_for_x86() {
        // 기본 36바이트 + 인자 개수 x 7바이트
        for cnt in 0..=6u8 {
            let code = builder(Architecture::X86)
                .make_shell_code(cnt)
                .unwrap()
                .build();
            assert_eq!(code.len(), 36 + cnt as usize * 7, "cnt={cnt}");
        }
    }
}
