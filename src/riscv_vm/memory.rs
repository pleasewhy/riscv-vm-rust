use crate::riscv_core::riscv::{RiscByte, RiscvHalf, RiscvWord};
use riscv_decode::Instruction;

const MASK_LOW: usize = 0xffff;
const MASK_HIGH: usize = 0x0000ffff;

const MEMORY_SIZE: usize = 0x100000000;
pub struct Chunk {
    data: [u8; 0x10000],
}

impl Chunk {
    pub fn new() -> Self {
        Chunk { data: [0; 0x10000] }
    }
}

pub struct Memory {
    chunks: Vec<Option<Box<Chunk>>>,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryError {
    AccessError,
}
pub type Result<T> = core::result::Result<T, MemoryError>;

impl Memory {
    pub fn new() -> Self {
        let mut mem = Memory { chunks: vec![] };
        for i in 0..0xffff {
            mem.chunks.push(None);
        }
        mem
    }

    /// Return the Instruction in $addr.
    pub fn read_inst(&self, addr: usize) -> Result<Instruction> {
        let addr_low = addr & MASK_LOW;
        assert!((addr_low & 3) == 0); // 指令要求4字节对齐
        let chunk = &self.chunks[(addr >> 16) as usize];
        if chunk.is_none() {
            return Err(MemoryError::AccessError);
        }
        let chunk = chunk.as_ref().unwrap();
        unsafe {
            let raw_inst = *(&chunk.data[addr_low as usize] as *const u8 as usize as *const u32);
            Ok(riscv_decode::decode(raw_inst).expect("decode instruction error."))
        }
    }

    pub fn write_by_iter(&mut self, addr: usize, iter: impl IntoIterator<Item = u8>) {
        let mut idx = 0;
        for b in iter {
            let write_to_addr = addr + idx;
            let write_to_addr_low = write_to_addr & MASK_LOW;
            let chunk_idx = write_to_addr >> 16;
            if let None = &self.chunks[chunk_idx] {
                self.chunks[chunk_idx] = Some(Box::new(Chunk::new()));
            }
            unsafe {
                self.chunks[chunk_idx].as_mut().unwrap().data[write_to_addr_low] = b;
            }
            idx += 1;
        }
    }

    /// write the data pointed to by %src to addr.
    pub fn write_by_ptr(&mut self, addr: usize, src: *const u8, size: usize) {
        for idx in 0..size {
            let write_to_addr = addr + idx;
            let write_to_addr_low = write_to_addr & MASK_LOW;
            let chunk_idx = write_to_addr >> 16;
            if let None = &self.chunks[chunk_idx] {
                self.chunks[write_to_addr >> 16] = Some(Box::new(Chunk::new()));
            }
            unsafe {
                self.chunks[chunk_idx].as_mut().unwrap().data[write_to_addr_low] =
                    *((src as usize + idx) as *const u8);
            }
        }
    }

    /// Read the exact number of bytes required to fill buf.
    pub fn read_by_buf(&self, addr: usize, buf: &mut [u8]) {
        // 在一个chunk中
        if (addr & MASK_HIGH) == ((addr + buf.len()) & MASK_HIGH) {
            if let Some(chunk) = &self.chunks[(addr >> 16) as usize] {
                let addr_low = addr & MASK_LOW;
                for idx in 0..buf.len() {
                    buf[idx] = chunk.data[addr_low + idx];
                }
            } else {
                buf.fill(0);
            }
        } else {
            // 不在一个chunk中
            for idx in 0..buf.len() {
                let read_from_addr = addr + idx;
                let read_from_addr_low = read_from_addr & MASK_LOW;
                let chunk_idx = read_from_addr >> 16;
                if let Some(chunk) = &self.chunks[chunk_idx] {
                    buf[idx] = chunk.data[read_from_addr_low + idx];
                } else {
                    buf[idx] = 0;
                }
            }
        }
    }

    /// Read a word from memory.
    pub fn read_word(&self, addr: usize) -> Result<RiscvWord> {
        assert!(addr < MEMORY_SIZE);
        let addr_low = addr & MASK_LOW;
        // 判断读取的word是否在一个chunk中
        if addr_low <= 0xfffc {
            let chunk = &self.chunks[(addr >> 16) as usize];
            if chunk.is_none() {
                return Ok(0);
            }
            let chunk = chunk.as_ref().unwrap();
            unsafe {
                Ok(*(&chunk.data[addr_low as usize] as *const u8 as usize as *const RiscvWord))
            }
        } else {
            let mut word = [0u8; core::mem::size_of::<RiscvWord>()];
            self.read_by_buf(addr, &mut word);
            unsafe { Ok(*(&word[0] as *const u8 as usize as *const RiscvWord)) }
        }
    }

    /// Read a half word from memory.
    pub fn read_half(&self, addr: usize) -> Result<RiscvHalf> {
        assert!(addr < MEMORY_SIZE);
        let addr_low = addr & MASK_LOW;
        // 判断读取的word是否在一个chunk中
        if addr_low <= 0xfffe {
            let chunk = &self.chunks[(addr >> 16) as usize];
            if chunk.is_none() {
                return Ok(0);
            }
            let chunk = chunk.as_ref().unwrap();
            unsafe {
                Ok(*(&chunk.data[addr_low as usize] as *const u8 as usize as *const RiscvHalf))
            }
        } else {
            let mut word = [0u8; core::mem::size_of::<RiscvHalf>()];
            self.read_by_buf(addr, &mut word);
            unsafe { Ok(*(&word[0] as *const u8 as usize as *const RiscvHalf)) }
        }
    }

    /// Read a byte from memory.
    pub fn read_byte(&self, addr: usize) -> Result<RiscByte> {
        assert!(addr < MEMORY_SIZE);
        let addr_low = addr & MASK_LOW;
        let chunk = &self.chunks[(addr >> 16) as usize];
        if chunk.is_none() {
            return Ok(0);
        }
        let chunk = chunk.as_ref().unwrap();
        unsafe { Ok(*(&chunk.data[addr_low as usize] as *const u8 as usize as *const RiscByte)) }
    }
}
