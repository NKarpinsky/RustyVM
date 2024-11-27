
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

    pub fn load(&mut self, address: usize, size: usize) -> Result<&[u8], ()> {
        for section in &self.sections {
            if section.base <= address && address <= section.base + section.size {
                let offset = address - section.base;
                let data = &section.memory[offset..offset+size];
                return Ok(data);
            }
        }
        return Err(());
    }

    pub fn load_u8(&mut self, address: usize) -> Result<u8, ()> {
        let data = self.load(address, 1)?;
        return Ok(data[0]);
    }

    pub fn load_u16(&mut self, address: usize) -> Result<u16, ()> {
        let data = self.load(address, 2)?;
        let result = u16::from_le_bytes(data.try_into().unwrap());
        return Ok(result);
    }

    pub fn load_u32(&mut self, address: usize) -> Result<u32, ()> {
        let data = self.load(address, 4)?;
        let result = u32::from_le_bytes(data.try_into().unwrap());
        return Ok(result);
    }

    pub fn load_u64(&mut self, address: usize) -> Result<u64, ()> {
        let data = self.load(address, 8)?;
        let result = u64::from_le_bytes(data.try_into().unwrap());
        return Ok(result);
    }

    pub fn store(&mut self, address: usize, value: &[u8]) -> Result<usize, ()> {
        for section in &mut self.sections {
            if section.base <= address && address <= section.base + section.size {
                let length = value.len();
                let offset = address - section.base;    
                section.memory[offset..offset+length].clone_from_slice(value);
                return Ok(value.len());
            }
        }
        return Err(());
    }

    

    pub fn store_u8(&mut self, address: usize, value: u8) -> Result<usize, ()> {
        let data = value.to_le_bytes();
        self.store(address, &data)
    }

    pub fn store_u16(&mut self, address: usize, value: u16) -> Result<usize, ()> {
        let data = value.to_le_bytes();
        self.store(address, &data)
    }

    pub fn store_u32(&mut self, address: usize, value: u32) -> Result<usize, ()> {
        let data = value.to_le_bytes();
        self.store(address, &data)
    }
    
    pub fn store_u64(&mut self, address: usize, value: u64) -> Result<usize, ()> {
        let data = value.to_le_bytes();
        self.store(address, &data)
    }

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