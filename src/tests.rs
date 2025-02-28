
#[cfg(test)]
mod memory_tests {
    use std::result;

    use crate::vm::memory_manager::MemoryManager;

    #[test]
    fn check_memory_mapping() {
        let mut mgr: MemoryManager = Default::default();
        let result = mgr.alloc(0x400000, 0x1000);
        assert!(result.is_ok());

        let result = mgr.alloc(0x500000, 0x1000);
        assert!(result.is_ok());

        let result = mgr.alloc(0x400000 - 0x50, 0x100);
        assert!(result.is_err());

        let result = mgr.alloc(0x400000 + 0x1000 - 0x50, 0x100);
        assert!(result.is_err());

        let result = mgr.alloc(0x400000, 0x1050);
        assert!(result.is_err());

        let result = mgr.alloc(0x400000 + 0x50, 0x100);
        assert!(result.is_err());
    }
    #[test]
    fn check_memory_usage() {
        let mut mgr: MemoryManager = Default::default();
        let result = mgr.alloc(0x400000, 0x100);
        assert!(result.is_ok());
        let result = mgr.store_u64(0x400000, 0xDEADBEEFC0FFEEAA);
        assert!(result.is_ok());
        let Ok(result) = mgr.load_u64(0x400000) else {assert!(false); return;};
        assert_eq!(result, 0xDEADBEEFC0FFEEAA);

        let target = [0xAA, 0xEE, 0xFF, 0xC0, 0xEf, 0xBE, 0xAD, 0xDE];

        for i in 0..8 {
            let Ok(result) = mgr.load_u8(0x400000+i) else {assert!(false); return; };
            assert_eq!(result, target[i]);
        }
        let target = [0xEEAA, 0xC0FF, 0xBEEF, 0xDEAD];
        for i in 0..4 {
            let Ok(result) = mgr.load_u16(0x400000+i*2) else {assert!(false); return; };
            assert_eq!(result, target[i]);
        }
        let target = [0xC0FFEEAA, 0xDEADBEEF];
        for i in 0..2 {
            let Ok(result) = mgr.load_u32(0x400000+i*4) else {assert!(false); return; };
            assert_eq!(result, target[i]);
        }
    }
}

#[cfg(test)]
mod vm_tests {
    use crate::vm::VirtualMachine;
    use crate::vm::bytecode::SpecicalRegisters::{rip, rsp};
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn run_nop_program() {
        let program_path = "tests_data/nop_program.rvm";
        let mut shellcode = vec![];
        File::open(program_path).unwrap().read_to_end(&mut shellcode);
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[rip as usize] - 0x400000, 4);
    }

    #[test]
    fn run_add_program() {
        let program_path = "tests_data/add_program.rvm";
        let mut shellcode = vec![];
        File::open(program_path).unwrap().read_to_end(&mut shellcode);
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[0], 0xDEADC0DE);
        assert_eq!(vm.regs[1], 0xC0FFEE);
        assert_eq!(vm.regs[2], 0xDEADC0DE + 0xC0FFEE);
    }
    #[test]
    fn run_sub_program() {
        let program_path = "tests_data/sub_program.rvm";
        let mut shellcode = vec![];
        File::open(program_path).unwrap().read_to_end(&mut shellcode);
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[0], 0xDEADC0DE - 0xDEADCE11);
        assert_eq!(vm.regs[1], 0xC0FFEE);
        assert_eq!(vm.regs[2], 0xDEADC0DE - 0xC0FFEE);
    }

    #[test]
    fn run_mul_div_program() {
        let program_path = "tests_data/mul_div_program.rvm";
        let mut shellcode = vec![];
        File::open(program_path).unwrap().read_to_end(&mut shellcode);
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[0], 0xDEADC0DE / 0xDEADCE11);
        assert_eq!(vm.regs[1], 0xC0FFEE);
        assert_eq!(vm.regs[2], 0xDEADC0DE * 0xC0FFEE);
    }

    #[test]
    fn run_shl_shr_program() {
        let program_path = "tests_data/shl_shr_program.rvm";
        let mut shellcode = vec![];
        File::open(program_path).unwrap().read_to_end(&mut shellcode);
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[0], 0xDEADC0DE >> 0x13);
        assert_eq!(vm.regs[1], 8);
        assert_eq!(vm.regs[2], 0xDEADC0DE << 8);
    }
    #[test]
    fn run_not_program() {
        let program_path = "tests_data/not_program.rvm";
        let mut shellcode = vec![];
        File::open(program_path).unwrap().read_to_end(&mut shellcode);
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[0], !0xDEADC0DE);
    }

    #[test]
    fn run_push_pop_program() {
        let shellcode = vec![0x43, 0x00, 0xde, 0xc0, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x0e, 0x01, 0x01];
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[1], 0xDEADC0DE);
    }

    #[test]
    fn many_push_pop_program() {
        let shellcode = vec![0x43, 0x00, 0xde, 0xc0, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0x43, 0x01, 0xEE, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0xDEADC0DE, r1 = 0xC0FFEE
                                               0xd, 0x00, 0xd, 0x01, 0xe, 0x02, 0xe, 0x03, 0x01];
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        // Sanity check
        assert_eq!(vm.regs[0], 0xDEADC0DE);
        assert_eq!(vm.regs[1], 0xC0FFEE);

        assert_eq!(vm.regs[2], 0xC0FFEE);
        assert_eq!(vm.regs[3], 0xDEADC0DE);
    }

    #[test]
    fn mov_reg_reg_program() {
        let shellcode = vec![0x02, 0x00, 0xde, 0xc0, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x01, 0x00, 0x01];  // mov r0, 0xDEADCODE -> mov r1, r0
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();

        assert_eq!(vm.regs[0], 0xDEADC0DE);
        assert_eq!(vm.regs[1], 0xDEADC0DE);
    }

    #[test]
    fn mov_reg_memory_program() {
        let shellcode = vec![0x02, 0x00, 0x08, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0xde, 0xc0, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, // mov r0, 0x500008 -> mov r1, 0xDEADC0DE
                                      0x82, 0x00, 0x01, 0x42, 0x02, 0x00, 0x01]; // mov [r0], r1 -> mov r2, [r0]
        let vm = VirtualMachine::from_shellcode(&shellcode);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();

        // Sanity check
        assert_eq!(vm.regs[0], 0x500008);
        assert_eq!(vm.regs[1], 0xDEADC0DE);

        assert_eq!(vm.regs[2], 0xDEADC0DE);
    }
}