
pub mod handlers {
    use crate::vm::{bytecode::SpecicalRegisters, VirtualMachine};
    use std::io::{self, Read};

    pub fn int_print(vm: &mut VirtualMachine) {
        let source_address = vm.regs[SpecicalRegisters::rsi as usize] as usize;
        let count = vm.regs[SpecicalRegisters::rcx as usize] as usize;
        let data = vm.mem.load(source_address, count).unwrap();
        println!("{}", String::from_utf8(data.to_vec()).unwrap());
    }

    pub fn int_read(vm: &mut VirtualMachine) {
        let dest_address = vm.regs[SpecicalRegisters::rdi as usize] as usize;
        let count = vm.regs[SpecicalRegisters::rcx as usize] as usize;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf);
        vm.mem.store(dest_address, buf[..count].as_bytes()); 
    }
}