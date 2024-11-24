mod vm;

use vm::VirtualMachine;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(program_path) = args.get(1) else {
        println!("Usage: rustyvm <path-to-program>");
        return;
    };
    let mut vm = VirtualMachine::new(&program_path);
    match vm {
        Ok(mut vm) => vm.execute(),
        Err(err) => println!("Error occured while loading program into virtual machine: {}", err.to_string())
    }
}
