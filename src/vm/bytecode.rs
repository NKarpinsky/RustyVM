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
            _ => Err(()),
        }
    }
}

pub mod handlers {
    use super::super::VirtualMachine;
    
    pub fn nop_handler(vm: &mut VirtualMachine) -> () {
        vm.rip += 1;
    }
    
    pub fn hlt_handler(vm: &mut VirtualMachine) -> () {
        vm.executing = false;
    }
    pub fn mov_handler(vm: &mut VirtualMachine) -> () {}
    
    pub fn add_handler(vm: &mut VirtualMachine) -> () {
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
            let constant = i64::from_le_bytes(
                vm.program[rip + 2..rip + 10]
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] += constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.rip += offset;
    }
    
    pub fn sub_handler(vm: &mut VirtualMachine) -> () {
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
            let constant = i64::from_le_bytes(
                vm.program[rip + 2..rip + 10]
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] -= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.rip += offset;
    }

    pub fn mul_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.rip.try_into().unwrap();
        let bytecode = vm.program[rip];
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
            let reg2_num: usize = vm.program[rip + 2].try_into().unwrap();
            vm.regs[reg1_num] *= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.program[rip + 2..rip + 10]
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] *= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.rip += offset;
    }

    pub fn div_handler(vm: &mut VirtualMachine) -> () {
        let rip: usize = vm.rip.try_into().unwrap();
        let bytecode = vm.program[rip];
        let operand_1_is_register = bytecode & 0b1000000; // now always must be a register
        let operand_2_is_register = bytecode & 0b10000000;
        let mut offset = 0;
        if operand_1_is_register != 0 && operand_2_is_register != 0 {
            let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
            let reg2_num: usize = vm.program[rip + 2].try_into().unwrap();
            vm.regs[reg1_num] /= vm.regs[reg2_num];
            offset = 3;
        }
        if operand_1_is_register != 0 && operand_2_is_register == 0 {
            let reg1_num: usize = vm.program[rip + 1].try_into().unwrap();
            let constant = i64::from_le_bytes(
                vm.program[rip + 2..rip + 10]
                    .try_into()
                    .expect("Invalid constant size in bytecode"),
            );
            vm.regs[reg1_num] /= constant;
            offset = 10;
        }
        if offset == 0 {
            panic!("Invalid bytecode!");
        }
        vm.rip += offset;
    }
}
