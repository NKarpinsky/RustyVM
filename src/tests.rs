use super::vm::VirtualMachine;

#[cfg(test)]
mod tests {
    use crate::vm::VirtualMachine;

    
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
        assert_eq!(vm.rip, 4);
    }
}