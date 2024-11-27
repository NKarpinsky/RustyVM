pub mod bytecode;
pub mod memory_manager;

use std::{error::Error, fs, io::Read};
use std::collections::HashMap;

use bytecode::Bytecode;
use bytecode::handlers::*;
use memory_manager::MemoryManager;
use bytecode::SpecicalRegisters::{rip, cs};


type BytecodeHandler = fn (&mut VirtualMachine) -> ();

pub struct VirtualMachine {
    pub regs: [i64; 256],
    pub rflags: u8,
    executing: bool,
    handlers: HashMap<Bytecode, BytecodeHandler>,
    mem_mgr: MemoryManager
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

    pub fn from_shellcode(bytes: &[u8]) -> Result<VirtualMachine, Box<dyn Error>> {
        let mut vm = VirtualMachine {
            regs: [0; 256],
            rflags: 0,
            handlers: init_handlers(),
            executing: false,
            mem_mgr: Default::default(),
        };
        let base_address = 0x400000;
        vm.mem_mgr.alloc(base_address, bytes.len())?;
        vm.regs[cs as usize] = base_address.try_into()?;
        vm.regs[rip as usize] = base_address.try_into()?;
        return Ok(vm);
    }

    pub fn new(path: &str) -> Result<VirtualMachine, Box<dyn Error>> {
        let mut file = fs::File::open(path)?;
        let mut buf: Vec<u8> = vec![];
        let result = file.read_to_end(&mut buf)?;
        Ok(VirtualMachine {
            regs: [0; 256], 
            rflags: 0, 
            handlers: init_handlers(), 
            executing: false,
            mem_mgr: Default::default()})
    }

    pub fn execute(&mut self) {
        self.executing = true;
        while self.executing {
            let _rip: usize = self.regs[rip as usize].try_into().unwrap();
            let Ok(opcode) = self.mem_mgr.load_u8(_rip) else { return; };
            let bytecode = opcode.try_into().expect("Unknown bytecode");
            self.handlers[&bytecode](self);
        }
    }
}