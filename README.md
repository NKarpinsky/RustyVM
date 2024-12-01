# RustyVM

Simple virtual machine project for learning Rust!

## Usage
```./rustyvm <path-to-program>```
## Memory management
Rusty VM use section-based memory manager. Every section determines by it's base address and size. Thats why there is no segment registers.
Program can allocate/deallocate memory throw syscall.

When you constructing shellcode, memory manager always will allocate two sections: one for shellcode and one for stack.
## Tasks
- [x] Bytecode execution
- [x] Arithmetic opcodes (add, sub, not, xor, shl, shr, etc.)
- [x] Memory mapping (stack, heap, etc.)
- [x] Memory opcodes (mov)
- [x] Control flow opcodes (cmp, jmp, je, jne, jge, etc.) 
- [x] Program format and loader
- [x] Interrupts/Syscalls (int)

## Architecture
* Machine has 256 64-bit register
* You can do any operation with any register
* Some registers has special meaning (instruction pointer, stack pointer, etc)
* Flags register can not be accesed by machine operations
* Now sections don't have access flags, but it could be added in the future
