mod bytecode;

use std::{error::Error, fs, io::Read};
use std::collections::HashMap;
use bytecode::Bytecode;
use bytecode::handlers::*;


type BytecodeHandler = fn (&mut VirtualMachine) -> ();

pub struct VirtualMachine {
    pub regs: [i64; 256],
    pub rip: u64,
    pub rflags: u8,
    pub program: Vec<u8>,
    executing: bool,
    handlers: HashMap<Bytecode, BytecodeHandler>
}



fn init_handlers() -> HashMap<Bytecode, BytecodeHandler> {
    let mut handlers = HashMap::new();
    handlers.insert(Bytecode::Nop, nop_handler as BytecodeHandler); 
    handlers.insert(Bytecode::Hlt, hlt_handler as BytecodeHandler);
    handlers.insert(Bytecode::Mov, mov_handler as BytecodeHandler);
    handlers.insert(Bytecode::Add, add_handler as BytecodeHandler);
    handlers.insert(Bytecode::Sub, sub_handler as BytecodeHandler);
    handlers.insert(Bytecode::Mul, mul_handler as BytecodeHandler);
    handlers.insert(Bytecode::Div, div_handler as BytecodeHandler);
    handlers.insert(Bytecode::Shl, shl_handler as BytecodeHandler);
    handlers.insert(Bytecode::Shr, shr_handler as BytecodeHandler);
    handlers.insert(Bytecode::Xor, xor_handler as BytecodeHandler);
    handlers.insert(Bytecode::And, and_handler as BytecodeHandler);
    handlers.insert(Bytecode::Or, or_handler as BytecodeHandler);
    handlers.insert(Bytecode::Not, not_handler as BytecodeHandler);

    return handlers;
}

impl VirtualMachine {

    pub fn new(path: &str) -> Result<VirtualMachine, Box<dyn Error>> {
        let mut file = fs::File::open(path)?;
        let mut buf: Vec<u8> = vec![];
        let result = file.read_to_end(&mut buf)?;
        Ok(VirtualMachine {regs: [0; 256], rip: 0, rflags: 0, program: buf, handlers: init_handlers(), executing: false})
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