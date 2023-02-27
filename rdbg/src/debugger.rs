//! Implementation of the `Debugger` struct which allows spawning a process, 
//! running it, placing breakpoints, reading and writing its memory etc.

use std::ffi::{CString, c_void};
use std::collections::{HashMap, HashSet, BTreeMap};

use crate::windows::{HANDLE, Handle, PROCESS_CREATION_FLAGS, ContinueStatus, 
    DebugEvent, EXCEPTION_RECORD};
use crate::windows::{self, CreateProcessA, WaitForDebugEvent, 
    ContinueDebugEvent, IsWow64Process, GetMappedFileNameW, ReadProcessMemory, 
    WriteProcessMemory, FlushInstructionCache};
use crate::dbg_callbacks::DbgCallbacks;
use crate::context::Context;

/// The number of milliseconds to wait for a debugging event. If this parameter 
/// is zero, the function tests for a debugging event and returns immediately. 
/// If the parameter is u32::MAX, the function does not return until a 
/// debugging event has occurred.
const DEBUGGER_TIMEOUT: u32 = 1000;

/// Whether to print a message for every debug event received
const DEBUG: bool = false;

/// Whether to output the debuggee's stdout
/// Note that this currently blocks (forever) if the child didn't output anything
const PIPE_STDOUT: bool = false;

/// Whether to output the debuggee's stderr 
/// Note that this currently blocks (forever) if the child didn't output anything
const PIPE_STDERR: bool = false;

/// Type of the closure called when a breakpoint is hit.
/// Arguments are: (dbg: Debugger, pid: u32, tid: u32, exception: EXCEPTION_RECORD)
pub type BreakpointCallback = dyn FnMut(&mut Debugger, u32, u32, &EXCEPTION_RECORD);

struct Breakpoint {
    addr: *mut c_void,
    /// The byte that was overwritten with 0xCC
    overwritten_byte: u8,
    cb: Box<BreakpointCallback>,
    // If `false`, this breakpoint gets deleted after the first hit 
    // If `true`, the breakpoint is triggered every time `addr` is reached
    permanent: bool,
}

impl Breakpoint {
    fn new(addr: *mut c_void, overwritten_byte: u8,
           cb: Box<BreakpointCallback>, permanent: bool) -> Self {
        Self {
            addr,
            overwritten_byte,
            cb,
            permanent
        }
    }
}

enum PostEventAction {
    Continue(ContinueStatus),
    Stop(u32),
}

/// Communication channels with the child.
struct ChildIo {
    // The parent writes to `stdin_write`
    stdin_write: Handle,
    // The parent reads from `stdout_read`
    stdout_read: Handle,
    // The parent reads from `stderr_read`
    stderr_read: Handle,
}

impl ChildIo {
    fn new() -> (Self, Handle, Handle, Handle) {
        let (stdin_read, stdin_write) = windows::create_pipe();
        windows::make_not_inheritable(&stdin_write);
        let (stdout_read, stdout_write) = windows::create_pipe();
        windows::make_not_inheritable(&stdout_read);
        let (stderr_read, stderr_write) = windows::create_pipe();
        windows::make_not_inheritable(&stderr_read);
        (Self {
            stdin_write,
            stdout_read,
            stderr_read,
        }, stdin_read, stdout_write, stderr_write)
    }
}

pub struct Debugger {
    process_handle: HANDLE,
    thread_handles: HashMap<u32, HANDLE>,
    modules: HashMap<String, *const c_void>,
    /// Map module_start -> (module_name, module_end) 
    resolve_modules: BTreeMap<usize, (String, usize)>,
    /// A context used as backing for SetThreadContext/GetThreadContext calls
    /// or their WOW64 equivalent. This avoids having to allocate a buffer
    /// every time we need to access a thread context.
    context: Context,
    /// Map: IP -> Breakpoint
    breakpoints: Option<HashMap<*mut c_void, Breakpoint>>,
    /// Breakpoints requested before the corresponding module was loaded. 
    /// They will be registered when the module is loaded.
    /// module_name -> Vec<off, callback, permanent>
    pending_breakpoints: HashMap<String, Vec<(usize, Box<BreakpointCallback>, bool)>>,
    /// Set of TIDs that are currently single stepping
    single_stepping: HashSet<u32>,
    child_io: Option<ChildIo>,
    /// If Some, 0xCC will be written to that address on the next single step
    bp_to_replace: Option<*mut u8>
}

impl Debugger {
    /// Spawn a new process under the debugger.
    /// NOTE `cmdline` includes the program path
    /// e.g cmdline = ["program_path", "arg1", "arg2", "arg3"]
    pub fn spawn(cmdline: &[&str], stdin: Option<String>) -> Self {
        let mut startup_info = windows::STARTUPINFOA::default();

        let inherit_handles;

        // Keep a reference to stdin_read, stdout_write, stderr_write until 
        // after CreateProcessA is called so that they don't get dropped (and
        // therefore closed with CloseHandle too early)
        let (child_io, _stdin_read, _stdout_write, _stderr_write) = 
        if stdin.is_some() {
            let (child_io, stdin_read, stdout_write, stderr_write) = ChildIo::new();
            startup_info.dwFlags = windows::STARTUPINFOA_FLAGS::STARTF_USESTDHANDLES;
            startup_info.hStdError  = stderr_write.0;
            startup_info.hStdOutput = stdout_write.0;
            startup_info.hStdInput  = stdin_read.0;
            inherit_handles = true;
            (Some(child_io), stdin_read, stdout_write, stderr_write)
        } else { 
            inherit_handles = false;
            // Return NONE and INVALID_HANDLE_VALUE
            (None, Handle(usize::MAX), Handle(usize::MAX), Handle(usize::MAX))
        };

        let mut proc_info = std::mem::MaybeUninit::zeroed();

        let cmdline = CString::new(cmdline.join(" ")).unwrap();

        let proc_info = unsafe {
            assert!(CreateProcessA(std::ptr::null_mut(),
                cmdline.into_raw(),
                std::ptr::null_mut(), // lpProcessAttributes
                std::ptr::null_mut(), // lpThreadAttributes
                inherit_handles, // bInheritHandles
                PROCESS_CREATION_FLAGS::DEBUG_ONLY_THIS_PROCESS as u32, // dwCreationFlags
                std::ptr::null_mut(), // lpEnvironment
                std::ptr::null_mut(), // lpCurrentDirectory
                &mut startup_info, // lpStartupInfo
                proc_info.as_mut_ptr()), // lpProcessInformation
            "CreateProcessA failed with {}", std::io::Error::last_os_error());

            // CreateProcessA successfully initialized the structure
            proc_info.assume_init()
        };

        let mut thread_handles = HashMap::new();
        thread_handles.insert(proc_info.dwThreadId, proc_info.hThread);

        let mut is_wow64 = false; 

        unsafe { 
            assert!(IsWow64Process(proc_info.hProcess, &mut is_wow64),
            "IsWow64Process failed with {}", std::io::Error::last_os_error());
        }

        if let Some(data) = stdin {
            windows::write_file(&child_io.as_ref().unwrap().stdin_write, data.as_bytes());
        }

        Self {
            process_handle: proc_info.hProcess,
            thread_handles: thread_handles,
            modules: HashMap::new(),
            resolve_modules: BTreeMap::new(),
            breakpoints: Some(HashMap::new()),
            pending_breakpoints: HashMap::new(),
            context: Context::new(is_wow64),
            single_stepping: HashSet::new(),
            bp_to_replace: None,
            child_io,
        }
    }

    fn handle_event(&mut self, debug_event: &DebugEvent, 
                    hit_initial_bp: &mut bool, 
                    cbs: &mut impl DbgCallbacks) -> PostEventAction {

        if DEBUG { println!("{debug_event}"); }

        match debug_event {
            DebugEvent::Unused => {
                panic!("Invalid Debug Event received");
            },
            DebugEvent::Exception { pid, tid, ref exception_record, 
                first_chance} => {
                cbs.exception_cb(self, *pid, *tid, exception_record, 
                                 *first_chance != 0);

                match exception_record.ExceptionCode as u32 {
                    // Breakpoint | STATUS_WX86_BREAKPOINT
                    code @ (0x80000003 | 0x4000001F) => {

                        if !*hit_initial_bp {
                            if let Context::Wow64(_) = self.context {
                                if code == 0x4000001F {
                                    *hit_initial_bp = true;
                                }
                            } else {
                                *hit_initial_bp = true;
                            }
                            return PostEventAction::Continue(
                                        ContinueStatus::DBG_CONTINUE);
                        }

                        let mut breakpoints = self.breakpoints.take().unwrap();
                        let addr = &exception_record.ExceptionAddress;

                        self.set_ip(*tid, *addr as u64);
                        match breakpoints.get_mut(addr) {
                            Some(bp) => {
                                // Restore the overwritten instruction
                                self.write_mem(bp.addr as _, &[bp.overwritten_byte]);
                                self.flush_instruction_caches();
                                (bp.cb)(self, *pid, *tid, exception_record);
                                if bp.permanent {
                                    self.bp_to_replace = Some(*addr as _);
                                }
                            }
                            None => (),
                        }

                        // Put back
                        self.breakpoints = Some(breakpoints);
                        PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
                    }
                    // Single step / STATUS_WX86_SINGLE_STEP
                    0x80000004 | 0x4000001E => {
                        if let Some(addr) = self.bp_to_replace.take() {
                            self.write_mem(addr as _, &[0xcc]);
                        }
                        cbs.single_step_cb(self, *pid, *tid);
                        PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
                    }
                    // EXCEPTION_ACCESS_VIOLATION
                    0xC0000005 => {
                        cbs.access_violation_cb(self, *pid, *tid, 
                                                exception_record,
                                                *first_chance != 0);
                        PostEventAction::Continue(
                            ContinueStatus::DBG_EXCEPTION_NOT_HANDLED)
                    },
                    // EXCEPTION_ILLEGAL_INSTRUCTION
                    0xC000001D => {
                        cbs.illegal_inst_cb(self, *pid, *tid, 
                                            exception_record,
                                            *first_chance != 0);
                        PostEventAction::Continue(
                            ContinueStatus::DBG_EXCEPTION_NOT_HANDLED)
                    },
                    // EXCEPTION_INT_DIVIDE_BY_ZERO
                    0xC0000094 => {
                        cbs.div_by_zero_cb(self, *pid, *tid, 
                                           exception_record,
                                           *first_chance != 0);
                        PostEventAction::Continue(
                            ContinueStatus::DBG_EXCEPTION_NOT_HANDLED)
                    },
                    // EXCEPTION_STACK_OVERFLOW
                    0xC00000FD => {
                        cbs.stack_overflow_cb(self, *pid, *tid, 
                                              exception_record,
                                              *first_chance != 0);
                        PostEventAction::Continue(
                            ContinueStatus::DBG_EXCEPTION_NOT_HANDLED)
                    },
                    // RPC_S_SERVER_UNAVAILABLE
                    0x000006BA => {
                        PostEventAction::Continue(
                            ContinueStatus::DBG_EXCEPTION_NOT_HANDLED)
                    },
                    // CLRDBG_NOTIFICATION_EXCEPTION_CODE
                    0x4242420 => {
                        PostEventAction::Continue(
                            ContinueStatus::DBG_EXCEPTION_NOT_HANDLED)
                    },
                    code @ _ => {
                        panic!("Unhandled exception {code:#x?}");
                    }
                }
            }
            DebugEvent::CreateThread { pid, tid, h_thread, start_address, .. } 
            => {
                self.thread_handles.insert(*tid, *h_thread);
                let start_address = unsafe { 
                    std::mem::transmute::<_, *mut c_void>(*start_address) 
                };
                cbs.create_thread_cb(self, *pid, *tid, start_address, *h_thread);
                PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
            }
            DebugEvent::CreateProcess { pid, tid, h_file, h_process, h_thread, 
                image_base, start_address, .. } => {
                let image_name = self.addr_to_mod_name(*image_base);
                let image_size = self.get_mod_image_size(*image_base);
                let start_address = unsafe { 
                    std::mem::transmute::<_, *mut c_void>(*start_address) 
                };

                self.place_pending_breakpoints(&image_name, *image_base);
                self.modules.insert(image_name.clone(), *image_base);
                self.resolve_modules.insert(*image_base as usize, 
                                (image_name.clone(), *image_base as usize 
                                             + image_size as usize - 1));

                cbs.create_process_cb(self, *pid, *tid, &image_name, 
                                      *image_base as _, start_address,
                                      *h_file, *h_process, *h_thread);
                PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
            }
            DebugEvent::ExitThread { pid, tid, exit_code } => {
                cbs.exit_thread_cb(self, *pid, *tid, *exit_code);
                PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
            }
            DebugEvent::ExitProcess { tid, pid, exit_code } => {
                cbs.exit_process_cb(self, *pid, *tid, *exit_code);
                PostEventAction::Stop(*exit_code)
            }
            DebugEvent::LoadDll { pid, tid, base_of_dll, .. } => {
                let image_name = self.addr_to_mod_name(*base_of_dll);
                let image_size = self.get_mod_image_size(*base_of_dll);

                self.modules.insert(image_name.clone(), *base_of_dll);
                self.resolve_modules.insert(*base_of_dll as usize, 
                                (image_name.clone(), *base_of_dll as usize 
                                             + image_size as usize - 1));

                cbs.dll_load_cb(self, *pid, *tid, &image_name, *base_of_dll);
                PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
            }
            DebugEvent::UnloadDll { pid, tid, base_of_dll } => {
                cbs.dll_unload_cb(self, *pid, *tid, *base_of_dll);
                PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
            }
            DebugEvent::DebugString { pid, tid, debug_string_data, funicode, 
                debug_string_length } => {

                let mut buf = vec!();
                (0..*debug_string_length).for_each(|_| buf.push(0));
                self.read_mem(*debug_string_data as _, &mut buf);
                
                let dbgstr = if *funicode == 0 {
                    // ANSI string
                    String::from_utf8_lossy(&buf).to_string()
                } else {
                    "".to_string()
                };
                println!("{pid}:{tid} {dbgstr}");
                PostEventAction::Continue(ContinueStatus::DBG_CONTINUE)
            }
            DebugEvent::RipInfo { .. } => {
                panic!("Event RipInfo not handled");
            }
        }
    }

    /// Main debugging loop. We wait for debug events and handle them.
    /// Returns the process' exit code
    pub fn run(&mut self, cbs: &mut impl DbgCallbacks) -> u32 {
        let mut debug_event = DebugEvent::Unused;
        let mut hit_initial_bp = false;

        loop {
            if !unsafe {WaitForDebugEvent(&mut debug_event, DEBUGGER_TIMEOUT)} {
                eprintln!("Timeout {}", std::io::Error::last_os_error());
                continue;
            }

            match self.handle_event(&debug_event, &mut hit_initial_bp, cbs) {
                PostEventAction::Continue(status) => {
                    let (pid, tid) = debug_event.get_pid_tid();

                    if self.single_stepping.contains(&tid) {
                        self.single_step(tid, true);
                    }

                    unsafe { 
                        assert!(ContinueDebugEvent(pid, tid, status),
                            "ContinueDebugEvent failed with {}", 
                            std::io::Error::last_os_error());
                    }
                } 
                PostEventAction::Stop(r) => {
                    if PIPE_STDOUT {
                        if let Some(c_io) = &self.child_io {
                            let mut buf = [0u8; 512];
                            windows::read_file(&c_io.stdout_read, &mut buf);
                            println!("Child stdout: {}", 
                                     String::from_utf8_lossy(&buf));
                        }
                    }

                    if PIPE_STDERR {
                        if let Some(c_io) = &self.child_io {
                            let mut buf = [0u8; 512];
                            windows::read_file(&c_io.stderr_read, &mut buf);
                            println!("Child stderr: {}", 
                                     String::from_utf8_lossy(&buf));
                        }
                    }

                    return r;
                }
            }
        }
    }

    fn set_context(&mut self, tid: u32) {
        self.context.set_context(self.thread_handles[&tid]);
    }

    fn get_context(&mut self, tid: u32) {
        self.context.get_context(self.thread_handles[&tid]);
    }

    /// Attempts to read `buf.len()` bytes of memory at `addr` in the debugged
    /// process. Returns the number of bytes read.
    pub fn read_mem(&self, addr: *const u8, buf: &mut [u8]) -> usize {
        let mut bytes_read = 0;
        unsafe { 
            assert!(ReadProcessMemory(self.process_handle, addr, 
                          buf.as_mut_ptr(), buf.len(), &mut bytes_read),
                    "ReadProcessMemory failed with {}", 
                    std::io::Error::last_os_error());
        }
        bytes_read
    }

    /// Attempts to read `buf.len()` bytes of memory at `addr` in the debugged
    /// process. Returns the number of bytes written.
    pub fn write_mem(&self, addr: *mut u8, buf: &[u8]) -> usize {
        let mut bytes_written = 0;
        unsafe { 
            assert!(WriteProcessMemory(self.process_handle, addr, 
                          buf.as_ptr(), buf.len(), &mut bytes_written),
                    "WriteProcessMemory failed with {}", 
                    std::io::Error::last_os_error());
        }
        bytes_written
    }

    /// Attempts to resolve the provided address to (module_name, offset).
    /// If `addr` cannot be resolved, this will return ("", addr)
    pub fn resolve_addr(&self, addr: *const c_void) -> (String, usize) {
        let addr = addr as usize;
        if let Some((base, (name, end))) = 
            self.resolve_modules.range(..=addr).next_back() {

            if addr <= *end {
                (name.clone(), addr - base)
            } else { (String::new(), addr) }
        } else { (String::new(), addr) }
    }

    // Set single-stepping to true or false for a given thread
    fn single_step(&mut self, tid: u32, single_step: bool) {
        self.get_context(tid);
        self.context.set_trap_flag(single_step);
        self.set_context(tid);
    }

    /// Enable single stepping for thread `tid`
    pub fn enable_single_stepping(&mut self, tid: u32) {
        self.single_stepping.insert(tid);
    }

    /// Disable single stepping for thread `tid`. Has no effect if it was not 
    /// enabled
    pub fn disable_single_stepping(&mut self, tid: u32) {
        self.single_stepping.remove(&tid);
    }

    fn set_ip(&mut self, tid: u32, ip: u64) {
        self.get_context(tid);
        self.context.set_ip(ip);
        self.set_context(tid);
    }

    /// Parses a PE's headers to get the SizeOfImage field
    fn get_mod_image_size(&self, module_base: *const c_void) -> u32 {
        let mut mz_magic = [0u8; 2];
        self.read_mem(module_base as _, &mut mz_magic);
        assert!(mz_magic == [0x4D, 0x5A], "Invalid DOS header magic");

        let mut pe_header_off = [0u8; 4];
        self.read_mem((module_base as usize + 0x3C) as _, &mut pe_header_off);
        let pe_header_off = u32::from_le_bytes(pe_header_off);

        let pe_header = module_base as usize + pe_header_off as usize;
        let mut pe_magic = [0u8; 4];
        self.read_mem(pe_header as _, &mut pe_magic);

        assert!(pe_magic == [0x50, 0x45, 0, 0], "Invalid PE header magic");

        let mut size_of_image = [0u8; 4];
        self.read_mem((pe_header + 0x50) as _, &mut size_of_image);
        let size_of_image = u32::from_le_bytes(size_of_image);
        size_of_image
    }

    fn addr_to_mod_name(&self, base: *mut c_void) -> String {
        let mut buf = [0u16; 4096];
        let len = unsafe {
            GetMappedFileNameW(self.process_handle, base, buf.as_mut_ptr(), 
                               buf.len() as u32)
        };
        assert!(len != 0 && (len as usize) < buf.len(), 
                "GetMappedFileNameW failed with {}", 
                std::io::Error::last_os_error());

        let path = String::from_utf16(&buf[..len as usize]).unwrap();

        // Get the filename from the path
        std::path::Path::new(&path).file_name().unwrap().to_str().unwrap().into()
    }

    // Actually place a breakpoint (overwrite the addr with 0xcc etc.)
    fn place_breakpoint(&mut self, addr: *mut c_void, 
                        cb: Box<BreakpointCallback>, permanent: bool) {
        let mut overwritten_byte = [0u8];
        self.read_mem(addr as _, &mut overwritten_byte);
        self.write_mem(addr as _, &[0xcc]);
        self.flush_instruction_caches();
        self.breakpoints.as_mut().unwrap().insert(addr, 
            Breakpoint::new(addr, overwritten_byte[0], cb, permanent));
    }

    fn place_pending_breakpoints(&mut self, modname: &str, base: *mut c_void) {
        if let Some(v) = self.pending_breakpoints.remove(modname) {
            for (off, cb, perm) in v {
                self.place_breakpoint((base as usize + off) as _, cb, perm);
            }
        }
    }

    /// Registers a breakpoint at address <module>+off
    /// Upon reaching the address, the closure `cb` will be invoked. 
    /// If `permanent` is false, the breakpoint is deleted after it's hit once
    /// If `permanent` is true, the breakpoint triggers every time the address
    /// is reached.
    pub fn register_breakpoint(&mut self, module: &str, off: usize, 
                           cb: Box<BreakpointCallback>, permanent: bool) {
        match self.modules.get(module) {
            Some(base) => {
                self.place_breakpoint((*base as usize + off) as _, cb, permanent)
            }
            None => {
                match self.pending_breakpoints.get_mut(module) {
                    None => {
                        self.pending_breakpoints.insert(module.to_string(), 
                                                vec!((off, cb, permanent)));
                    }
                    Some(v) => {
                        v.push((off, cb, permanent));
                    }
                }
            }
        }
    }

    fn flush_instruction_caches(&self) {
        unsafe {
            assert!(FlushInstructionCache(self.process_handle, 
                                          std::ptr::null(), 0),
                    "FlushInstructionCache failed with {}", 
                    std::io::Error::last_os_error());
        }
    }
}
