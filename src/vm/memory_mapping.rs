

struct Section {
    base: usize,
    size: usize,
    memory: Vec<u8>
}

#[derive(Default)]
pub struct MemoryManager {
    sections: Vec<Section>
}

impl MemoryManager {

    pub fn alloc(&mut self, base: usize, size: usize) -> Result<(), &str> {
        for section in &self.sections {
            if (section.base..section.base+section.size).contains(&base) ||
               (section.base..section.base+section.size).contains(&(base + size)) ||
               (base < section.base && base + size > section.base + section.size) {
                    return Err("Can not allocate memory: Invalid mapping");
               }
        }
        let section = Section {
                base, size,
                memory: vec![0; size]
        };
        self.sections.push(section);
        Ok(())
    }

    pub fn dealloc(&mut self, base: usize) -> Result<(), &str> {
        let Some(index) = self.sections.iter().position(|x| x.base == base) else {
            return Err("Memory section does not exists!");
        };
            self.sections.remove(index);
            Ok(())
    }
}