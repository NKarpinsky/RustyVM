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
    Int
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
            _ => Err(())
        }
    }
}