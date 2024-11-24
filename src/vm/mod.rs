mod bytecode;

use std::thread::JoinHandle;
use std::{error::Error, fs, io::Read};
use std::collections::HashMap;
use bytecode::Bytecode;


type BytecodeHandler = fn (&mut VirtualMachine) -> ();

enum Registers {
    r0,
    r1,
    r2,
    r3,
}

pub struct VirtualMachine {
    pub r0: i64,
    pub r1: i64,
    pub r2: i64,
    pub r3: i64,
    pub rip: u64,
    pub rflags: u8,
    pub program: Vec<u8>,
    executing: bool,
    handlers: HashMap<Bytecode, BytecodeHandler>
}

fn nop_handler(vm: &mut VirtualMachine) -> () {
    vm.rip += 1;
}
fn hlt_handler(vm: &mut VirtualMachine) -> () {
    vm.executing = false;
}
fn mov_handler(vm: &mut VirtualMachine) -> () {}
fn add_handler(vm: &mut VirtualMachine) -> () {}
fn sub_handler(vm: &mut VirtualMachine) -> () {}

fn init_handlers() -> HashMap<Bytecode, BytecodeHandler> {
    let mut handlers = HashMap::new();
    handlers.insert(Bytecode::Nop, nop_handler as BytecodeHandler); 
    handlers.insert(Bytecode::Hlt, hlt_handler as BytecodeHandler);
    handlers.insert(Bytecode::Mov, mov_handler as BytecodeHandler);
    handlers.insert(Bytecode::Add, add_handler as BytecodeHandler);
    handlers.insert(Bytecode::Sub, sub_handler as BytecodeHandler);

    return handlers;
}

impl VirtualMachine {

    pub fn new(path: &str) -> Result<VirtualMachine, Box<dyn Error>> {
        let mut file = fs::File::open(path)?;
        let mut buf: Vec<u8> = vec![];
        let result = file.read_to_end(&mut buf)?;
        Ok(VirtualMachine {r0: 0, r1: 0, r2: 0, r3: 0, rip: 0, rflags: 0, program: buf, handlers: init_handlers(), executing: false})
    }

    pub fn execute(&mut self) {
        self.executing = true;
        while self.executing {
            let rip: usize = self.rip.try_into().unwrap();
            let opcode = self.program[rip];
            let bytecode = opcode.try_into().expect("Unknown bytecode");
            self.handlers[&bytecode](self);
        }
    }
}