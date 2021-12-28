use elf;
use elf::types::PT_LOAD;
use riscv_decode::{self, Instruction};
use std::env;
use std::os::unix::prelude::FileExt;
use std::path::PathBuf;

#[macro_use]
mod riscv_vm;
mod riscv_core;

fn main() {
    let insts = vec![0x04813823u32, 0x0005c783u32, 0x06010413u32, 0x00093783u32];
    for i in insts {
        let inst = riscv_decode::decode(i).unwrap();
        println!("{:?}", inst);
    }

    let path = PathBuf::from("test/helloworld");
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };
    println!("entry=0x{:x}", file.ehdr.entry);
    let mut mem = riscv_vm::memory::Memory::new();
    let mut io_file = std::fs::File::open(path).unwrap();
    io_file.read
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
            mem.write_by_iter(section.shdr.addr as usize, section.data);
        }
    }
    for ph in file.phdrs {
        println!(
            "phdr: vaddr=0x{:x} end=0x{:x} filesz=0x{:x} memsize=0x{:x}",
            ph.vaddr,
            ph.vaddr + ph.memsz,
            ph.filesz,
            ph.memsz
        );
    }

    let mut pc = file.ehdr.entry as usize;
    for i in 0..10000 {
        pc += 4;
    }
}
