use std::convert::TryFrom;

#[derive(PartialEq, Eq, Hash)]
pub enum Bytecode {
    Nop,
    Hlt,
    Mov,
    Add,
    Sub,
    Mul,
    Div,
    Shl,
    Shr,
    Xor,
    Not,
    And,
    Or,
    Push,
    Pop,
    Cmp,
    Jmp,
    Je,
    Jne,
    Jl,
    Jg,
    Int,
}

impl TryFrom<u8> for Bytecode {
    type Error = ();
    fn try_from(opcode: u8) -> Result<Self, ()> {
        let OPCODE_MASK = 0b111111;
        match opcode & OPCODE_MASK {
            x if x == Bytecode::Nop as u8 => Ok(Bytecode::Nop),
            x if x == Bytecode::Hlt as u8 => Ok(Bytecode::Hlt),
            x if x == Bytecode::Mov as u8 => Ok(Bytecode::Mov),
            x if x == Bytecode::Add as u8 => Ok(Bytecode::Add),
            x if x == Bytecode::Sub as u8 => Ok(Bytecode::Sub),
            x if x == Bytecode::Mul as u8 => Ok(Bytecode::Mul),
            x if x == Bytecode::Div as u8 => Ok(Bytecode::Div),
            x if x == Bytecode::Shl as u8 => Ok(Bytecode::Shl),
            x if x == Bytecode::Shr as u8 => Ok(Bytecode::Shr),
            x if x == Bytecode::Not as u8 => Ok(Bytecode::Not),
            x if x == Bytecode::And as u8 => Ok(Bytecode::And),
            x if x == Bytecode::Or as u8 => Ok(Bytecode::Or),
            x if x == Bytecode::Push as u8 => Ok(Bytecode::Push),
            x if x == Bytecode::Pop as u8 => Ok(Bytecode::Pop),
            _ => Err(()),
        }
    }
}

// All registers has names r0-r255, but some of them has spectial roles in opcodes.
// This register nums presented at this enum. They can be used as any other registers
pub enum SpecicalRegisters {
    rax,
    rbx,
    rcx,
    rdx,
    rdi,
    rsi,
    rbp,
    rsp,
    rip,
}

pub mod handlers {
    use super::super::VirtualMachine;
    use super::SpecicalRegisters;

    pub fn nop_handler(vm: &mut VirtualMachine) -> () {
        vm.regs[SpecicalRegisters::rip as usize] += 1;
    }

    pub fn hlt_handler(vm: &mut VirtualMachine) -> () {
        vm.executing = false;
    }
    pub fn mov_handler(vm: &mut VirtualMachine) -> () {}

    pub fn push_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let reg_num = vm.mem.load_u8(rip + 1).unwrap();
        let rsp = &mut vm.regs[SpecicalRegisters::rsp as usize];
        *rsp += 8;
        let address: usize = (*rsp).try_into().unwrap();
        let result = vm.mem.store(address, &vm.regs[reg_num as usize].to_le_bytes());
        if result.is_err() {
            panic!("Stack overflow!");
        }
    }

    pub fn pop_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let reg_num = vm.mem.load_u8(rip + 1).unwrap();
        let rsp = &mut vm.regs[SpecicalRegisters::rsp as usize];
        let address: usize = (*rsp).try_into().unwrap();
        let Ok(result) = vm.mem.load(address, 8) else {
            panic!("Can not access stack memory!");
        };
        *rsp -= 8;
        let result: i64 = i64::from_le_bytes(result.try_into().unwrap());
        vm.regs[reg_num as usize] = result;
    }

    pub fn add_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] += vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] += constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn sub_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] -= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] -= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn mul_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] *= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] *= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn div_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] /= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] /= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn shl_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] <<= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] <<= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn shr_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] >>= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] >>= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn xor_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] ^= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] ^= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn and_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] &= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] &= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn or_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let bytecode = vm.mem.load_u8(rip).unwrap();
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let reg2_num: usize = vm.mem.load_u8(rip + 2).unwrap().try_into().unwrap();
            vm.regs[reg1_num] |= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.mem.load(rip + 2, 8).unwrap()
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] |= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.regs[SpecicalRegisters::rip as usize] += offset;
    }

    pub fn not_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.regs[SpecicalRegisters::rip as usize].try_into().unwrap();
        let reg_num: usize = vm.mem.load_u8(rip + 1).unwrap().try_into().unwrap(); // two flag bits of NOT instruction can be any
        vm.regs[reg_num] = !vm.regs[reg_num];
        vm.regs[SpecicalRegisters::rip as usize] += 2;
    }
}
