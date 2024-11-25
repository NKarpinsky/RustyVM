

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

    fn alloc(&mut self, base: u64, size: u64) -> Result<(), String> {
        Ok(())
    }

    fn dealloc(&mut self, base: u64) -> Result<(), String> {
        Ok(())
    }
}