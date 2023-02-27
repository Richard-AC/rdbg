//! Trait that can be implemented to get callbacks when specific debugging 
//! events are reached

use std::ffi::c_void;
use crate::debugger::Debugger;
use crate::windows::{HANDLE, EXCEPTION_RECORD};

pub trait DbgCallbacks {
    fn exception_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32, 
                    _exception: &EXCEPTION_RECORD, 
                    _first_chance_: bool) {}

    fn create_thread_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32, 
                        _start_address: *mut c_void,
                        _h_thread:      HANDLE) {}

    fn create_process_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32,
                         _image_name: &str,
                         _image_base: *mut c_void,
                         _start_address: *mut c_void,
                         _h_file: HANDLE,
                         _h_process: HANDLE,
                         _h_thread: HANDLE) {}

    fn exit_thread_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32, 
                      _exit_code: u32) {}

    fn exit_process_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32, 
                       _exit_code: u32) {}

    fn dll_load_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32, 
                   _image_name: &str, 
                   _base_of_dll: *mut c_void) {}

    fn dll_unload_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32, 
                     _base_of_dll: *mut c_void) {}

    fn access_violation_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32,
                           _exception: &EXCEPTION_RECORD,
                           _first_chance_: bool) {}

    fn single_step_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32) {}

    fn illegal_inst_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32,
                       _exception: &EXCEPTION_RECORD,
                       _first_chance_: bool) {}

    fn div_by_zero_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32,
                      _exception: &EXCEPTION_RECORD,
                      _first_chance_: bool) {}

    fn stack_overflow_cb(&mut self, _dbg: &mut Debugger, _pid: u32, _tid: u32,
                         _exception: &EXCEPTION_RECORD,
                         _first_chance_: bool) {}
}
