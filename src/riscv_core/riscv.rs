use super::consts::rv_reg_zero;
use super::consts::REGISTER_NUM;
use crate::riscv_vm::memory;
use riscv_decode::Instruction;

pub type RiscvWord = u32;
pub type RiscvHalf = u16;
pub type RiscByte = u8;
pub type RiscvFloat = f32;

pub type riscv_mem_fetch_inst = Box<dyn Fn()>;

struct RiscvCore {
    regs: [RiscvWord; REGISTER_NUM],
    PC: RiscvWord,
    mem: memory::Memory,
}

#[inline]
fn cal_addr(rv: &RiscvCore, reg: u32, imm: u32) -> usize {
    (rv.regs[reg as usize] + imm) as usize
}

/// sign extend a 16 bit value
#[inline]
fn sign_extend_h(val: u16) -> u32 {
    (val as i16) as i32 as u32
}

/// sign extend a 8 bit value
#[inline]
fn sign_extend_b(val: u8) -> u32 {
    (val as i8) as i32 as u32
}

fn op_load(rv: &mut RiscvCore, inst: Instruction) {
    let rd;
    match inst {
        Instruction::Lb(itype) => {
            let addr = cal_addr(rv, itype.rs1(), itype.imm());
            rd = itype.rd() as usize;
            rv.regs[rd] = sign_extend_b(rv.mem.read_byte(addr as usize).unwrap());
        }
        Instruction::Lh(itype) => {
            let addr = cal_addr(rv, itype.rs1(), itype.imm());
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] = sign_extend_h(rv.mem.read_half(addr as usize).unwrap());
        }
        Instruction::Lw(itype) => {
            let addr = cal_addr(rv, itype.rs1(), itype.imm());
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] = rv.mem.read_word(addr as usize).unwrap() as u32;
        }
        Instruction::Lbu(itype) => {
            let addr = cal_addr(rv, itype.rs1(), itype.imm());
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] = rv.mem.read_byte(addr as usize).unwrap() as u32;
        }
        Instruction::Lhu(itype) => {
            let addr = cal_addr(rv, itype.rs1(), itype.imm());
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] = rv.mem.read_half(addr as usize).unwrap() as u32;
        }
        _ => panic!("invalid instruction"),
    }
    rv.PC += 4;
    if rv_reg_zero == rd as u8 {
        rv.regs[0] = 0;
    }
}
