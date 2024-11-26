#[cfg(test)]
mod tests {
    use crate::vm::VirtualMachine;
    use crate::vm::bytecode::SpecicalRegisters::rip;
    
    #[test]
    fn run_nop_program() {
        let program_path = "tests_data/nop_program.rvm";
        let vm = VirtualMachine::new(&program_path);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[rip as usize], 4);
    }

    #[test]
    fn run_add_program() {
        let program_path = "tests_data/add_program.rvm";
        let vm = VirtualMachine::new(&program_path);
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
        let vm = VirtualMachine::new(&program_path);
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
        let program = "tests_data/mul_div_program.rvm";
        let vm = VirtualMachine::new(&program);
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
        let program = "tests_data/shl_shr_program.rvm";
        let vm = VirtualMachine::new(&program);
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
        let program = "tests_data/not_program.rvm";
        let vm = VirtualMachine::new(&program);
        assert!(vm.is_ok());
        let Ok(mut vm) = vm else {
            assert!(false);
            return;
        };
        vm.execute();
        assert_eq!(vm.regs[0], !0xDEADC0DE);
    }
}