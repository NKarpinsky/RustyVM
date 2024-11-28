# RustyVM

Simple virtual machine project for learning Rust!

### Currently in progress...
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
- [ ] Interrupts/Syscalls (int)
- [ ] Simple assembler program
