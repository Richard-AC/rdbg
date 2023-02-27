use rdbg::debugger::Debugger;
use rdbg::dbg_callbacks::DbgCallbacks;

/// An analysis which counts the number of single steps during the debuggee's 
/// execution.
struct SingleStepCounter(usize);

impl DbgCallbacks for SingleStepCounter {
    // This function gets called on each single step
    fn single_step_cb(&mut self, _: &mut Debugger, _: u32, _: u32) {
        self.0 += 1;
    }
}

fn attempt(pass: &str) -> usize {
    // Spawn chall.exe under the debugger without providing any stdin (this 
    // challenge accepts input on argv).
    let mut dbg = Debugger::spawn(&["examples\\crackme_example\\chall.exe", pass], Some(String::new()));

    // Start single stepping when we reach the `call check_password` instruction
    dbg.register_breakpoint("chall.exe", 0x10DB, Box::new(|dbg, _pid, tid, _exception| {
        dbg.enable_single_stepping(tid);
    }), false);

    // Stop single stepping when we return from `check_password`
    dbg.register_breakpoint("chall.exe", 0x10E0, Box::new(|dbg, _pid, tid, _exception| {
        dbg.disable_single_stepping(tid);
    }), false);

    let mut single_step_counter = SingleStepCounter(0);
    dbg.run(&mut single_step_counter);
    single_step_counter.0
}

fn main() {
    let alphabet = ('!'..='~').into_iter().collect::<Vec<char>>();

    let mut x = String::from("___________ ");

    for i in 0..6 {
        let mut m = 0;
        let mut next_char = ' ';
        for c in &alphabet {
            x.replace_range(i..i+1, &c.to_string());
            let ss = attempt(&x[..7]);

            if ss > m { 
                m = ss;
                next_char = *c;
            }
        }

        x.replace_range(i..i+1, &next_char.to_string());
        println!("{x}");
    }
}
