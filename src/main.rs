#![feature(get_mut_unchecked)]

use elf;
use elf::types::PT_LOAD;
use riscv_core::riscv::RiscvCore;
use riscv_decode::{self, Instruction};
use riscv_vm::memory::Memory;
use std::env;
use std::fmt::Debug;
use std::os::unix::prelude::FileExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use simple_logger::SimpleLogger;

#[macro_use]
mod riscv_vm;
mod riscv_core;

fn main() {
    SimpleLogger::new().init().unwrap();
    let path = PathBuf::from("test/helloworld");
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };
    println!("entry=0x{:x}", file.ehdr.entry);
    let mut mem = Arc::new(Mutex::new(Memory::new()));
    let mut core = RiscvCore::new(mem.clone());
    core.PC = file.ehdr.entry as u32;
    let mut sz = 0;
    for section in file.sections {
        if section.shdr.addr != 0 {
            println!(
                "write mem: name={} addr=0x{:x}, end=0x{:x}, size=0x{:x} data.size=0x{:x}",
                section.shdr.name,
                section.shdr.addr,
                section.shdr.addr + section.shdr.size,
                section.shdr.size,
                section.data.len()
            );
            sz += section.shdr.size;
            mem.lock()
                .unwrap()
                .write_by_iter(section.shdr.addr as usize, section.data);
        }
    }
    core.regs[riscv_core::consts::rv_reg_sp as usize] = (sz + 4096) as u32;
    let inst = riscv_decode::decode(0xfa5ff06f).unwrap();
    if let Instruction::Jal(b) = inst {
        println!("{:?},0x{:x}", inst, b.imm());
    }
    riscv_core::riscv::rv_step(&mut core, 100);
}
