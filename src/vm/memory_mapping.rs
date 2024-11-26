

struct Section {
    base: u64,
    size: u64,
    memory: Box<[u8]>
}

#[derive(Default)]
pub struct MemoryManager {
    sections: Vec<Section>
}

impl MemoryManager {

    pub fn alloc(&mut self, base: u64, size: u64) -> Result<(), String> {
        Ok(())
    }

    pub fn dealloc(&mut self, base: u64) -> Result<(), String> {
        let Some(index) = self.sections.iter().position(|x| x.base == base) else {
            return Err("Memory section does not exists!".to_string());
        };
            self.sections.remove(index);
            Ok(())
    }
}