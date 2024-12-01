pub mod bytecode;
pub mod memory_manager;
pub mod loader;

use std::{error::Error, fs, io::Read};
use std::collections::HashMap;

use bytecode::{Bytecode, SpecicalRegisters};
use bytecode::handlers::*;
use memory_manager::MemoryManager;
use bytecode::SpecicalRegisters::{rip, rsp};


type BytecodeHandler = fn (&mut VirtualMachine) -> ();

pub struct VirtualMachine {
    pub regs: [i64; 256],
    pub rflags: u8,
    executing: bool,
    handlers: HashMap<Bytecode, BytecodeHandler>,
    mem: MemoryManager
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
    handlers.insert(Bytecode::Push, push_handler as BytecodeHandler);
    handlers.insert(Bytecode::Pop, pop_handler as BytecodeHandler);
    handlers.insert(Bytecode::Mov, mov_handler as BytecodeHandler);
    handlers.insert(Bytecode::Cmp, cmp_handler as BytecodeHandler);
    handlers.insert(Bytecode::Jmp, jmp_handler as BytecodeHandler);
    handlers.insert(Bytecode::Jc, jc_handler as BytecodeHandler);
    handlers.insert(Bytecode::Call, call_handler as BytecodeHandler);
    handlers.insert(Bytecode::Ret, ret_handler as BytecodeHandler);

    return handlers;
}

impl VirtualMachine {

    pub fn from_shellcode(shellcode: &[u8]) -> Result<VirtualMachine, Box<dyn Error>> {
        let mut vm = VirtualMachine {
            regs: [0; 256],
            rflags: 0,
            handlers: init_handlers(),
            executing: false,
            mem: Default::default(),
        };
        let base_address = 0x400000;
        let stack_address = 0x500000;
        vm.mem.alloc(base_address, shellcode.len())?;   // allocating memory for shellcode
        vm.mem.store(base_address, shellcode);
        vm.regs[rip as usize] = base_address.try_into()?;

        vm.mem.alloc(stack_address, 0x1000)?;   // allocating memory for stack
        vm.regs[rsp as usize] = stack_address.try_into()?;
        vm.regs[rsp as usize] += 0x1000;                 // stack growth to little addresses
        return Ok(vm);
    }

    fn load_program(path: &str) -> Result<(MemoryManager, i64, i64), Box<dyn Error>> {
        let mut file = fs::File::open(path)?;
        let mut buf: Vec<u8> = vec![];
        let result = file.read_to_end(&mut buf)?;
        if !buf.starts_with(b"RVM_") {
                return Err("Magic is not verified!".into());
        }

        let count_of_sections = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let mut mem = MemoryManager::default();
        let mut stack_address = Default::default();
        let mut executable_address = Default::default();
        for i in 0..count_of_sections {
            let section_info = &buf[8+12*i..8+12*(i+1)];
            let base_address = usize::from_le_bytes(section_info[..4].try_into().unwrap());
            let size = usize::from_le_bytes(buf[4..8].try_into().unwrap());
            let params = usize::from_le_bytes(buf[8..12].try_into().unwrap());
            mem.alloc(base_address, size)?;
            if params & 1 == 1 {     // MAPPED
                let offset = params >> 3;
                mem.store(base_address, &buf[offset..offset+size]);
            }
            if params & 0b10 != 0 {  // STACK
                stack_address = (base_address + size) as i64;
            }
            if params & 0b100 != 0 { // EXECUTABLE
                executable_address = base_address as i64;
            }
        }

        return Ok((mem, stack_address, executable_address));
    }

    pub fn new(path: &str) -> Result<VirtualMachine, Box<dyn Error>> {
        let (mem, stack_address, executable_address) = VirtualMachine::load_program(path)?;
        let mut vm = VirtualMachine {
            regs: [0; 256], 
            rflags: 0, 
            handlers: init_handlers(), 
            executing: false,
            mem
        };
        vm.regs[SpecicalRegisters::rsp as usize] = stack_address;
        vm.regs[SpecicalRegisters::rip as usize] = executable_address;
        Ok(vm)
    }

    pub fn execute(&mut self) {
        self.executing = true;
        while self.executing {
            let _rip: usize = self.regs[rip as usize].try_into().unwrap();
            let Ok(opcode) = self.mem.load_u8(_rip) else { return; };
            let bytecode = opcode.try_into().expect("Unknown bytecode");
            self.handlers[&bytecode](self);
        }
    }
}