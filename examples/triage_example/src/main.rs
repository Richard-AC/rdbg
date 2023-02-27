use rdbg::debugger::Debugger;
use rdbg::dbg_callbacks::DbgCallbacks;
use rdbg::windows::EXCEPTION_RECORD;

/// An analysis which prints information about a crashing program
struct CrashAnalysis;
impl DbgCallbacks for CrashAnalysis {
    fn access_violation_cb(&mut self, dbg: &mut Debugger, _pid: u32, _tid: u32, 
                           exception: &EXCEPTION_RECORD, first_chance: bool) {

        let addr = exception.ExceptionAddress;        

        // Resolve the address to module + offset
        let (module, offset) = dbg.resolve_addr(addr);

        let details = if exception.NumberParameters > 1 {
            let a = exception.ExceptionInformation[1];
            let av_type = match exception.ExceptionInformation[0] {
                0 => "read",
                1 => "write",
                8 => "exec",
                _ => unreachable!(),
            };

            format!("Invalid {av_type} to {a:#x}")
        } else { String::new() };

        println!("Access Violation @ {module}+{offset:#x} ({} chance). {}",
                 if first_chance { "first" } else { "second" }, details);
    }
}

fn main() {
    let mut dbg = Debugger::spawn(&["examples\\triage_example\\crash.exe"], None);
    dbg.run(&mut CrashAnalysis);
}
