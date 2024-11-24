use std::thread::JoinHandle;
use std::{error::Error, fs, io::Read};
use std::collections::HashMap;

#[derive(PartialEq, Eq, Hash)]
enum Bytecode {
    Nop,
    Hlt,
    Mov,
    Add,
    Sub,
    Mul,
    Div,
    Shl,
    Shr,
    Jmp,
    Je,
    Jne,
    Jl,
    Jg,
    Not,
    And,
    Or,
    Cmp,
    Xor,
    Int
}

type BytecodeHandler = fn (&mut VirtualMachine) -> ();

enum Registers {
    r0,
    r1,
    r2,
    r3,
}

pub struct VirtualMachine {
    r0: i64,
    r1: i64,
    r2: i64,
    r3: i64,
    rip: u64,
    rflags: u8,
    program: Vec<u8>,
    handlers: HashMap<Bytecode, BytecodeHandler>
}

fn nop_handler(vm: &mut VirtualMachine) -> () {}
fn hlt_handler(vm: &mut VirtualMachine) -> () {}
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
        Ok(VirtualMachine {r0: 0, r1: 0, r2: 0, r3: 0, rip: 0, rflags: 0, program: buf, handlers: init_handlers()})
    }

    pub fn execute(&self) {
    }
}