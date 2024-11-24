use std::{error::Error, fs, io::Read};


enum Bytecode {
    Nop,
    Ret,
    Hlt,
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
pub struct VirtualMachine {
    r0: i64,
    r1: i64,
    r2: i64,
    r3: i64,
    rip: u64,
    memory: Vec<u8>
}

impl VirtualMachine {

    pub fn new(path: &str) -> Result<VirtualMachine, Box<dyn Error>> {
        let mut file = fs::File::open(path)?;
        let mut buf: Vec<u8> = vec![];
        let result = file.read_to_end(&mut buf)?;
        Ok(VirtualMachine {r0: 0, r1: 0, r2: 0, r3: 0, rip: 0, memory: buf})
    }

    pub fn execute(&self) {

    }
}