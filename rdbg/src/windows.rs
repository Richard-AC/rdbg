//! This file provides some rust bindings to the Windows native API.
//! The naming convention is that UPPERCASE types are raw C types while 
//! CamelCase types are rust wrappers.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ffi::c_void;

// Types
pub type HANDLE     = usize;
pub type HKEY       = usize;
pub type LPCSTR     = *mut i8;
pub type LPSTR      = *mut i8;
pub type LPWSTR     = *mut u16;
pub type NTSTATUS   = i32;
pub type LPTHREAD_START_ROUTINE = 
    Option<unsafe extern "system" fn(lpthreadparameter: *mut c_void) -> u32>;

/// `Handle` is a rust wrapper arround HANDLE which is the raw value.
/// Its main purpose is automatically closing the handle when dropped.
#[derive(Debug)]
pub struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    nLength: u32,
    lpSecurityDescriptor: *mut c_void,
    bInheritHandle: bool,
}

#[repr(C)]
pub struct STARTUPINFOA {
    cb: u32,
    lpReserved: LPSTR,
    lpDesktop: LPSTR,
    lpTitle: LPSTR,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    pub dwFlags: STARTUPINFOA_FLAGS,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

impl Default for STARTUPINFOA {
    fn default() -> Self {
        Self {
            cb: core::mem::size_of::<STARTUPINFOA>() as u32,
            lpReserved: std::ptr::null_mut(),
            lpDesktop: std::ptr::null_mut(),
            lpTitle: std::ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: STARTUPINFOA_FLAGS::NONE,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: 0,
            hStdOutput: 0,
            hStdError: 0,
        }
    }
}

/// Add as needed
#[repr(u32)]
pub enum STARTUPINFOA_FLAGS {
    NONE                    = 0,
    STARTF_FORCEONFEEDBACK  = 0x00000040,
    STARTF_USESTDHANDLES    = 0x00000100,
}

/// Add as needed
#[repr(u32)]
pub enum PROCESS_CREATION_FLAGS {
    DEBUG_ONLY_THIS_PROCESS = 0x00000002,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess    : HANDLE,
    pub hThread     : HANDLE,
    pub dwProcessId : u32,
    pub dwThreadId  : u32,
}

#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: NTSTATUS,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}

#[repr(u32)]
pub enum ExceptionCode {
    DBG_CONTINUE              = 0x00010002,
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001,
    DBG_REPLY_LATER           = 0x40010001
}

// #[repr(C, u32)] // This doesn't work in x64 because it pads the tag to 
// 64 bits which messes up everything
#[repr(u32)] // This is so HOT! https://rust-lang.github.io/rfcs/2195-really-tagged-unions.html
pub enum DebugEvent {
    Unused, // For some reason, dwDebugEventCode is 1-indexed https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-debug_event
    Exception {
        pid: u32,
        tid: u32,
        exception_record: EXCEPTION_RECORD,
        first_chance: u32
    },
    CreateThread {
        pid: u32,
        tid: u32,
        h_thread: HANDLE, 
        tls_base: *mut c_void, 
        start_address: LPTHREAD_START_ROUTINE
    },
    CreateProcess {
        pid: u32,
        tid: u32,
        h_file: HANDLE, 
        h_process: HANDLE, 
        h_thread: HANDLE, 
        image_base: *mut c_void, 
        debug_info_file_offset: u32, 
        debug_info_size: u32, 
        tls_base: *mut c_void, 
        start_address: LPTHREAD_START_ROUTINE,
        image_name: *mut c_void,
        funicode: u16
    },
    ExitThread {
        pid: u32,
        tid: u32,
        exit_code: u32
    },
    ExitProcess {
        pid: u32, 
        tid: u32, 
        exit_code: u32 
    },
    LoadDll {
        pid: u32, 
        tid: u32, 
        h_file: HANDLE, 
        base_of_dll: *mut c_void,
        debug_info_file_offset: u32, 
        debug_info_size: u32, 
        image_name: *mut c_void, 
        funicode: u16
    },
    UnloadDll {
        pid: u32,
        tid: u32,
        base_of_dll: *mut c_void
    },
    DebugString {
        pid: u32, 
        tid: u32, 
        debug_string_data: LPSTR, 
        funicode: u16,
        debug_string_length: u16
    },
    RipInfo {
        pid: u32,
        tid: u32, 
        error: u32, 
        typ: u32
    }
}


impl std::fmt::Display for DebugEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugEvent::Unused => {
                write!(f, "DebugEvent::Invalid")
            },
            DebugEvent::Exception { pid, tid, ..} => {
                write!(f, "[{:x}:{:x}] DebugEvent::Exception", *pid, *tid)
            }
            DebugEvent::CreateThread { pid, tid, .. } 
            => {
                write!(f, "[{:x}:{:x}] DebugEvent::CreateThread", *pid, *tid)
            }
            DebugEvent::CreateProcess { pid, tid, .. } => {
                write!(f, "[{:x}:{:x}] DebugEvent::CreateProcess", *pid, *tid)
            }
            DebugEvent::ExitThread { pid, tid, exit_code } => {
                write!(f, "[{:x}:{:x}] DebugEvent::ExitThread (code:{:#x})", 
                       *pid, *tid, *exit_code)
            }
            DebugEvent::ExitProcess { tid, pid, exit_code } => {
                write!(f, "[{:x}:{:x}] DebugEvent::ExitProcess (code:{:#x})", 
                       *pid, *tid, *exit_code)
            }
            DebugEvent::LoadDll { pid, tid, .. } => {
                write!(f, "[{:x}:{:x}] DebugEvent::LoadDll", *pid, *tid)
            }
            DebugEvent::UnloadDll { pid, tid, .. } => {
                write!(f, "[{:x}:{:x}] DebugEvent::UnloadDll", *pid, *tid)
            }
            DebugEvent::DebugString { pid, tid, .. } => {
                write!(f, "[{:x}:{:x}] DebugEvent::DebugString", *pid, *tid)
            }
            DebugEvent::RipInfo { pid, tid, .. } => {
                write!(f, "[{:x}:{:x}] DebugEvent::RipInfo", *pid, *tid)
            }
        }
    }
}

impl DebugEvent {
    pub fn get_pid_tid(&self) -> (u32, u32) {
        match self {
            DebugEvent::Unused => {
                panic!("Invalid Debug Event");
            },
            DebugEvent::Exception { pid, tid, .. }
            | DebugEvent::CreateThread { pid, tid, .. }
            | DebugEvent::CreateProcess { pid, tid, .. }
            | DebugEvent::ExitThread { pid, tid, .. }
            | DebugEvent::ExitProcess { pid, tid, .. }
            | DebugEvent::LoadDll { pid, tid, .. }
            | DebugEvent::UnloadDll { pid, tid, .. }
            | DebugEvent::DebugString { pid, tid, .. }
            | DebugEvent::RipInfo { pid, tid, .. } => {
                (*pid, *tid)
            }
        }
    }
}

/// Add as needed
#[repr(u32)]
pub enum ContinueStatus {
    DBG_CONTINUE              = 0x00010002,
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001,
    DBG_REPLY_LATER           = 0x40010001
}

/// Creates a PIPE and returns (ReadHandle, WriteHandle)
pub fn create_pipe() -> (Handle, Handle) {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true,
    };

    let mut r_handle = 0;
    let mut w_handle = 0;

    unsafe {
        assert!(CreatePipe(&mut r_handle, &mut w_handle, 
                           &mut sa as *mut SECURITY_ATTRIBUTES as _, 0),
                "CreatePipe Failed with {}", std::io::Error::last_os_error());
    }

    assert!(r_handle != 0 && w_handle != 0, 
            "Invalid handle returned by CreatePipe");

    (Handle(r_handle), Handle(w_handle))
}

pub fn make_not_inheritable(h: &Handle) {
    unsafe { assert!(SetHandleInformation(h.0, 1, 0)); }

}

pub fn read_file(h: &Handle, buf: &mut [u8]) {
    let mut bytes_written = 0;
    unsafe {
        assert!(ReadFile(h.0, buf.as_ptr() as _, buf.len() as u32, 
                          &mut bytes_written, std::ptr::null()),
                "ReadFile Failed with {}", std::io::Error::last_os_error());
    }
}

pub fn write_file(h: &Handle, buf: &[u8]) {
    let mut bytes_written = 0;
    unsafe {
        assert!(WriteFile(h.0, buf.as_ptr() as _, buf.len() as u32, 
                          &mut bytes_written, std::ptr::null()),
                "WriteFile Failed with {}", std::io::Error::last_os_error());
    }
}

/// Get the size of a file on disk
pub fn get_file_size(h: HANDLE) -> u64 {
    let mut size = 0;
    unsafe {
        assert!(GetFileSizeEx(h, &mut size), 
            "GetFileSizeEx Failed with {}", std::io::Error::last_os_error());
    }
    size as u64
}

#[link(name="kernel32")]
extern "system" {
    pub fn CreateProcessA(
        lpApplicationName    : LPCSTR,
        lpCommandLine        : LPSTR,
        lpProcessAttributes  : *mut SECURITY_ATTRIBUTES,
        lpThreadAttributes   : *mut SECURITY_ATTRIBUTES,
        bInheritHandles      : bool,
        dwCreationFlags      : u32,
        lpEnvironment        : *mut c_void,
        lpCurrentDirectory   : LPCSTR,
        lpStartupInfo        : *mut STARTUPINFOA,
        lpProcessInformation : *mut PROCESS_INFORMATION) -> bool;

    pub fn CloseHandle(hObject: HANDLE) -> bool;

    pub fn WaitForDebugEvent(
        lpDebugEvent    : *mut DebugEvent, 
        dwMilliseconds  : u32) -> bool;

    pub fn ContinueDebugEvent(
        dwProcessId     : u32,
        dwThreadId      : u32,
        dwContinueStatus: ContinueStatus) -> bool;

    pub fn IsWow64Process(
        hProcess    : HANDLE,
        Wow64Process: *mut bool) -> bool;

    pub fn ReadProcessMemory(
        hProcess            : HANDLE, 
        lpBaseAddress       : *const u8,
        lpBuffer            : *mut u8,
        nSize               : usize,
        lpNumberOfBytesRead : *mut usize) -> bool;

    pub fn WriteProcessMemory(
        hProcess                : HANDLE, 
        lpBaseAddress           : *mut u8,
        lpBuffer                : *const u8,
        nSize                   : usize,
        lpNumberOfBytesWritten  : *mut usize) -> bool;

    pub fn FlushInstructionCache (
        hProcess        : HANDLE,
        lpBaseAddress   : *const c_void,
        dwSize          : usize) -> bool;

    fn CreatePipe(
        hReadPipe       : *mut HANDLE,
        hWritePipe      : *mut HANDLE,
        lpPipeAttributes: *mut c_void,
        nSize           : u32) -> bool;

    fn SetHandleInformation(
        hObject : HANDLE,
        dwMask  : u32,
        dwFlags : u32) -> bool;

    pub fn ReadFile(
        hFile               : HANDLE,
        lpBuffer            : *mut c_void,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead : *mut u32,
        lpOverlapped        : *const c_void) -> bool;

    pub fn WriteFile(
        hFile                   : HANDLE,
        lpBuffer                : *const c_void,
        nNumberOfBytesToWrite   : u32,
        lpNumberOfBytesWritten  : *mut u32,
        lpOverlapped            : *const c_void) -> bool;

    fn GetFileSizeEx(
        hFile       : HANDLE,
        lpFileSize  : *mut i64) -> bool;
}

#[link(name="psapi")]
extern "system" {
    pub fn GetMappedFileNameW(
        hProcess    : HANDLE,
        lpv         : *const c_void, 
        lpFilename  : LPWSTR,
        nSize       : u32) -> u32;
}
