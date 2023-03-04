//! FFI helpers to interact with Windows thread contexts.
//! It exposes a single enum: `Context` which allows interacting transparently 
//! with native and Wow64 contexts.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::windows::HANDLE;

#[repr(C)]
#[derive(Default, Debug)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    //pub Reserved4: [u8; 96], 
    // Rust doesn't implement Default for arrays bigger than 32 so I split it 
    pub Reserved4_1: [u8; 32],
    pub Reserved4_2: [u8; 32],
    pub Reserved4_3: [u8; 32],
}

#[repr(C, align(16))]
#[derive(Default, Debug)]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: XSAVE_FORMAT,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

impl std::fmt::Display for CONTEXT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rax={:#018x} Rbx={:#018x} Rcx={:#018x}\n\
                   Rdx={:#018x} Rsi={:#018x} Rdi={:#018x}\n\
                   Rip={:#018x} Rsp={:#018x} Rbp={:#018x}\n\
                   R8 ={:#018x} R9 ={:#018x} R10={:#018x}\n\
                   R11={:#018x} R12={:#018x} R13={:#018x}\n\
                   R14={:#018x} R15={:#018x} EFL={:#010x}", 
                   self.Rax, self.Rbx, self.Rcx, self.Rdx, self.Rsi, self.Rdi,
                   self.Rip, self.Rsp, self.Rbp, self.R8, self.R9, self.R10,
                   self.R11, self.R12, self.R13, self.R14, self.R15, 
                   self.EFlags)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct WOW64_FLOATING_SAVE_AREA {
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; 80],
    pub Cr0NpxState: u32,
}

impl Default for WOW64_FLOATING_SAVE_AREA {
    fn default() -> Self {
        Self {
            ControlWord: 0,
            StatusWord: 0,
            TagWord: 0,
            ErrorOffset: 0,
            ErrorSelector: 0,
            DataOffset: 0,
            DataSelector: 0,
            RegisterArea: [0u8; 80],
            Cr0NpxState: 0
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct WOW64_CONTEXT {
    pub ContextFlags: u32,
    pub Dr0: u32,
    pub Dr1: u32,
    pub Dr2: u32,
    pub Dr3: u32,
    pub Dr6: u32,
    pub Dr7: u32,
    pub FloatSave: WOW64_FLOATING_SAVE_AREA,
    pub SegGs: u32,
    pub SegFs: u32,
    pub SegEs: u32,
    pub SegDs: u32,
    pub Edi: u32,
    pub Esi: u32,
    pub Ebx: u32,
    pub Edx: u32,
    pub Ecx: u32,
    pub Eax: u32,
    pub Ebp: u32,
    pub Eip: u32,
    pub SegCs: u32,
    pub EFlags: u32,
    pub Esp: u32,
    pub SegSs: u32,
    pub ExtendedRegisters: [u8; 512],
}

impl std::fmt::Display for WOW64_CONTEXT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Eax={:#010x} Ebx={:#010x} Ecx={:#010x}\n\
                   Edx={:#010x} Esi={:#010x} Edi={:#010x}\n\
                   Eip={:#010x} Esp={:#010x} Ebp={:#010x}\n\
                   EFL={:#010x}", 
                   self.Eax, self.Ebx, self.Ecx, self.Edx, self.Esi, self.Edi,
                   self.Eip, self.Esp, self.Ebp, self.EFlags)
    }
}

impl Default for WOW64_CONTEXT {
    fn default() -> Self {
        Self {
            ContextFlags: 0,
            Dr0: 0,
            Dr1: 0,
            Dr2: 0,
            Dr3: 0,
            Dr6: 0,
            Dr7: 0,
            FloatSave: WOW64_FLOATING_SAVE_AREA::default(),
            SegGs: 0,
            SegFs: 0,
            SegEs: 0,
            SegDs: 0,
            Edi: 0,
            Esi: 0,
            Ebx: 0,
            Edx: 0,
            Ecx: 0,
            Eax: 0,
            Ebp: 0,
            Eip: 0,
            SegCs: 0,
            EFlags: 0,
            Esp: 0,
            SegSs: 0,
            ExtendedRegisters: [0u8; 512],
        }
    }
}

#[derive(Debug)]
pub enum Context {
    Native(CONTEXT),
    Wow64(WOW64_CONTEXT),
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(c) => {
                write!(f, "{}", c)
            }
            Self::Wow64(c) => {
                write!(f, "{}", c)
            }
        }
    }
}

impl Context {
    pub fn new(wow64: bool) -> Self {
        if wow64 {
            let mut context = WOW64_CONTEXT::default();
            context.ContextFlags = 0x10001f; // CONTEXT_ALL
            Self::Wow64(context)
        } else {
            let mut context = CONTEXT::default();
            context.ContextFlags = 0x10001f; // CONTEXT_ALL
            Self::Native(context)
        }
    }

    pub fn get_context(&mut self, h_thread: HANDLE) {
        match self {
            Self::Native(ref mut c) => {
                unsafe {
                    assert!(
                        GetThreadContext(h_thread, c),
                        "GetThreadContext failed with {}", 
                        std::io::Error::last_os_error());
                }
            }
            Self::Wow64(ref mut c) => {
                unsafe {
                    assert!(
                        Wow64GetThreadContext(h_thread, c),
                        "Wow64GetThreadContext failed with {}", 
                        std::io::Error::last_os_error());
                }
            }
        }
    }

    pub fn set_context(&self, h_thread: HANDLE) {
        match self {
            Self::Native(ref c) => {
                unsafe {
                    assert!(
                        SetThreadContext(h_thread, c),
                        "SetThreadContext failed with {}", 
                        std::io::Error::last_os_error());
                }
            }
            Self::Wow64(ref c) => {
                unsafe {
                    assert!(
                        Wow64SetThreadContext(h_thread, c),
                        "Wow64SetThreadContext failed with {}", 
                        std::io::Error::last_os_error());
                }
            }
        }
    }

    /// Get the instruction pointer
    pub fn get_ip(&mut self) -> u64 {
        match self {
            Self::Native(c) => {
                c.Rip
            }
            Self::Wow64(c) => {
                c.Eip as u64
            }
        }
    }

    /// Set the instruction pointer
    pub fn set_ip(&mut self, ip: u64) {
        match self {
            Self::Native(ref mut c) => {
                c.Rip = ip;
            }
            Self::Wow64(ref mut c) => {
                c.Eip = ip as u32;
            }
        }
    }

    /// Get the stack pointer
    pub fn get_sp(&mut self) -> u64 {
        match self {
            Self::Native(c) => {
                c.Rsp
            }
            Self::Wow64(c) => {
                c.Esp as u64
            }
        }
    }

    /// Set the stack pointer
    pub fn set_sp(&mut self, sp: u64) {
        match self {
            Self::Native(ref mut c) => {
                c.Rsp = sp;
            }
            Self::Wow64(ref mut c) => {
                c.Esp = sp as u32;
            }
        }
    }

    /// Get the accumulator register (Eax / Rax)
    pub fn get_acc(&mut self) -> u64 {
        match self {
            Self::Native(c) => {
                c.Rax
            }
            Self::Wow64(c) => {
                c.Eax as u64
            }
        }
    }

    /// Set the accumulator register (Eax / Rax)
    pub fn set_acc(&mut self, acc: u64) {
        match self {
            Self::Native(ref mut c) => {
                c.Rax = acc;
            }
            Self::Wow64(ref mut c) => {
                c.Eax = acc as u32;
            }
        }
    }

    pub fn set_trap_flag(&mut self, v: bool) {
        match self {
            Self::Native(ref mut c) => {
                if v {
                    c.EFlags |= 1 << 8;
                } else {
                    c.EFlags &= !(1 << 8)
                }
            }
            Self::Wow64(ref mut c) => {
                if v {
                    c.EFlags |= 1 << 8;
                } else {
                    c.EFlags &= !(1 << 8)
                }
            }
        }
    }
}

#[link(name="kernel32")]
extern "system" {
    pub fn GetThreadContext(
        hThread: HANDLE,
        lpContext: *mut CONTEXT) -> bool;

    pub fn SetThreadContext(
        hThread: HANDLE,
        lpContext: *const CONTEXT) -> bool;

    pub fn Wow64GetThreadContext(
        hThread: HANDLE,
        lpContext: *mut WOW64_CONTEXT) -> bool;

    pub fn Wow64SetThreadContext(
        hThread: HANDLE,
        lpContext: *const WOW64_CONTEXT) -> bool;
}
