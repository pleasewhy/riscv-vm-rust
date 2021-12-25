use elf;
use riscv_decode::{self, Instruction};
use std::env;
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
    println!("{:?}", file);
    let text_scn = match file.get_section(".text") {
        Some(s) => s,
        None => panic!("Failed to look up .text section"),
    };
    // println!("{:?}", text_scn.data);
}
