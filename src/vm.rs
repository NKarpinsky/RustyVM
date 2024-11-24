
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
    pub fn new(path: &str) {

    }
}