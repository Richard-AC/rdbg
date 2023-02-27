# rdbg

`rdbg` is a rust library for writing Windows debuggers.

For more details and some use cases, read the 
[associated blogpost](https://richard-ac.github.io/posts/rdbg/).

# Features 

- Provides rust-friendly safe wrappers to the Windows debugging API
- Supports both native (64 bit) and Wow64 (32 bit) processes transparently
- It has no dependencies

# Overview 

`rdbg` is built arround two components: 

- The `Debugger` struct which allows spawning a processe, running it, placing
breakpoints, single stepping etc. 
- The `DbgCallbacks` trait which allows the user to define functions which will
be called on various debugging events (thread creation, dll loading, 
access violation, etc.)

## Debugger

The `Debugger` is used to spawn and run a process. Note that `spawn` accepts
an `Option<String>` for `stdin` which will be fed to the target process' 
stdin if provided.

```rust
/// Spawn a new process under the debugger.
/// e.g cmdline = ["program_path", "arg1", "arg2", "arg3"]
pub fn spawn(cmdline: &[&str], stdin: Option<String>) -> Self

/// Run the process returning its exit code
pub fn run(&mut self, cbs: &mut impl DbgCallbacks) -> u32
```

The `Debugger` can then be used to read and write the debuggee's memory:

```rust
/// Attempts to read `buf.len()` bytes of memory at `addr` in the debugged
/// process. Returns the number of bytes read.
pub fn read_mem(&self, addr: *const u8, buf: &mut [u8]) -> usize

/// Attempts to write `buf.len()` bytes of memory to `addr` in the debugged
/// process. Returns the number of bytes written.
pub fn write_mem(&self, addr: *mut u8, buf: &[u8]) -> usize
```

The `Debugger` can place breakpoints and provide a closure to be 
executed when the breakpoint is hit. If the module hasn't been loaded yet, 
the breakpoint is deferred and will be registered when the module gets loaded.

```rust
/// Registers a breakpoint at address <module>+off
/// Upon reaching the address, the closure `cb` will be invoked. 
/// If `permanent` is false, the breakpoint is deleted after it's hit once
/// If `permanent` is true, the breakpoint triggers every time the address
/// is reached.
pub fn register_breakpoint(&mut self, module: &str, off: usize, 
                       cb: Box<BreakpointCallback>, permanent: bool)

/// Type of the closure called when a breakpoint is hit.
/// Arguments are: (dbg: Debugger, pid: u32, tid: u32, exception: EXCEPTION_RECORD)
pub type BreakpointCallback = dyn FnMut(&mut Debugger, u32, u32, &EXCEPTION_RECORD);
```

Finally, we can single-step threads:

```rust
/// Enable single stepping for thread `tid`
pub fn enable_single_stepping(&mut self, tid: u32)

/// Disable single stepping for thread `tid`. Has no effect if it was not 
/// enabled
pub fn disable_single_stepping(&mut self, tid: u32)
```

## DbgCallbacks

This trait allows the user to provide functions that will get called when a
specific event occurs.

Here is the list of events currently available: 
```rust
/// Called when the debugged process causes an exception
fn exception_cb
/// Called on thread creation
fn create_thread_cb
/// Called on process creation
fn create_process_cb
/// Called on thread exit
fn exit_thread_cb
/// Called on process exit
fn exit_process_cb
/// Called on DLL load
fn dll_load_cb
/// Called on DLL unload
fn dll_unload_cb
/// Called when the debugged process causes an access violation
fn access_violation_cb
/// Called on every single step
fn single_step_cb
/// Called when the debugged process attempts to execute an illegal instruction
fn illegal_inst_cb
/// Called when the debugged process divides by zero
fn div_by_zero_cb
/// Called when the debugged process uses up its stack
fn stack_overflow_cb
```

The user should implement this trait on a struct and pass it to the 
`Debugger`'s `run` method.

```rust
struct MyAnalysis;
impl DbgCallbacks for MyAnalysis { }
...
let mut dbg = Debugger::spawn(&["program.exe"], None);
dbg.run(&mut MyAnalysis);
```

# Known bugs

Single stepping a WOW64 thread stops when the thread transitions to 64 bits 
(with `jmp  0033:<addr>`).
