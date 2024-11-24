mod bytecode;

use core::panic;
use std::thread::JoinHandle;
use std::{error::Error, fs, io::Read};
use std::collections::HashMap;
use bytecode::Bytecode;


type BytecodeHandler = fn (&mut VirtualMachine) -> ();

pub struct VirtualMachine {
    pub regs: [i64; 256],
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
fn add_handler(vm: &mut VirtualMachine) -> () {
    let rip: usize = vm.rip.try_into().unwrap();
    let bytecode = vm.program[rip];
    let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
    let operand_2_is_register = bytecode & 0b10000000;
    let mut offset = 0;
    if operand_1_is_register != 0 && operand_2_is_register != 0 {
        let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
        let reg2_num: usize = vm.program[rip + 2].try_into().unwrap();
        vm.regs[reg1_num] += vm.regs[reg2_num];
        offset = 3;
    }
    if operand_1_is_register != 0 && operand_2_is_register == 0 {
        let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
        let constant = i64::from_le_bytes(vm.program[rip+2..rip+10].try_into().expect("Invalid constant size in bytecode"));
        vm.regs[reg1_num] += constant;
        offset = 10;
    }
    if offset == 0 {
        panic!("Invalid bytecode!");
    }
    vm.rip += offset;
}
fn sub_handler(vm: &mut VirtualMachine) -> () {
    let rip: usize = vm.rip.try_into().unwrap();
    let bytecode = vm.program[rip];
    let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
    let operand_2_is_register = bytecode & 0b10000000;
    let mut offset = 0;
    if operand_1_is_register != 0 && operand_2_is_register != 0 {
        let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
        let reg2_num: usize = vm.program[rip + 2].try_into().unwrap();
        vm.regs[reg1_num] -= vm.regs[reg2_num];
        offset = 3;
    }
    if operand_1_is_register != 0 && operand_2_is_register == 0 {
        let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
        let constant = i64::from_le_bytes(vm.program[rip+2..rip+10].try_into().expect("Invalid constant size in bytecode"));
        vm.regs[reg1_num] -= constant;
        offset = 10;
    }
    if offset == 0 {
        panic!("Invalid bytecode!");
    }
    vm.rip += offset;
}

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