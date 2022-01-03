use super::consts::rv_reg_zero;
use super::consts::REGISTER_NUM;
use crate::riscv_core::consts::rv_reg_sp;
use crate::riscv_vm::memory;
use crate::riscv_vm::memory::Memory;
use riscv_decode::Instruction;
use std::sync::{Arc, Mutex};

pub type RiscvWord = u32;
pub type RiscvHalf = u16;
pub type RiscvByte = u8;
pub type RiscvFloat = f32;

pub type riscv_mem_fetch_inst = Box<dyn Fn()>;

pub struct RiscvCore {
    pub regs: [RiscvWord; REGISTER_NUM],
    pub PC: RiscvWord,
    pub mem: Arc<Mutex<Memory>>,
}

impl RiscvCore {
    pub fn new(mem: Arc<Mutex<Memory>>) -> Self {
        Self {
            regs: [0; REGISTER_NUM],
            PC: 0,
            mem: mem,
        }
    }
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

fn op_load(rv: &mut RiscvCore, inst: Instruction) -> bool {
    let rd;
    match inst {
        Instruction::Lb(itype) => {
            let addr = rv.regs[itype.rs1() as usize] as i32 + itype.imm_s_ext();
            rd = itype.rd() as usize;
            rv.regs[rd] = sign_extend_b(rv.mem.lock().unwrap().read_byte(addr as usize).unwrap());
        }
        Instruction::Lh(itype) => {
            let addr = rv.regs[itype.rs1() as usize] as i32 + itype.imm_s_ext();
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] =
                sign_extend_h(rv.mem.lock().unwrap().read_half(addr as usize).unwrap());
        }
        Instruction::Lw(itype) => {
            let addr = rv.regs[itype.rs1() as usize] as i32 + itype.imm_s_ext();
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] =
                rv.mem.lock().unwrap().read_word(addr as usize).unwrap() as u32;
            log::debug!(
                "rd={} val={} addr=0x{:x} sp={} imm={}",
                rd,
                rv.regs[itype.rd() as usize],
                addr,
                rv.regs[rv_reg_sp as usize] as i32,
                itype.imm_s_ext() as i32
            );
        }
        Instruction::Lbu(itype) => {
            let addr = rv.regs[itype.rs1() as usize] as i32 + itype.imm_s_ext();
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] =
                rv.mem.lock().unwrap().read_byte(addr as usize).unwrap() as u32;
        }
        Instruction::Lhu(itype) => {
            let addr = rv.regs[itype.rs1() as usize] as i32 + itype.imm_s_ext();
            rd = itype.rd() as usize;
            rv.regs[itype.rd() as usize] =
                rv.mem.lock().unwrap().read_half(addr as usize).unwrap() as u32;
        }
        _ => panic!("invalid instruction"),
    }
    rv.PC += 4;
    if rv_reg_zero == rd as u8 {
        rv.regs[0] = 0;
    }
    true
}

fn op_operate_imm(rv: &mut RiscvCore, inst: Instruction) -> bool {
    let rd;
    match inst {
        Instruction::Addi(itype) => {
            rd = itype.rd() as usize;
            rv.regs[rd] = ((rv.regs[itype.rs1() as usize] as i32) + itype.imm_s_ext()) as u32;
        }
        Instruction::Slli(shift_type) => {
            rd = shift_type.rd() as usize;
            rv.regs[rd] = shift_type.rs1() << (shift_type.shamt() & 0x1f);
        }
        Instruction::Slti(itype) => {
            rd = itype.rd() as usize;
            rv.regs[rd] = if (rv.regs[itype.rs1() as usize] as i32) < itype.imm_s_ext() {
                1
            } else {
                0
            };
        }
        Instruction::Sltiu(itype) => {
            rd = itype.rd() as usize;
            rv.regs[rd] = if rv.regs[itype.rs1() as usize] < (itype.imm_s_ext() as u32) {
                1
            } else {
                0
            };
        }
        Instruction::Xori(itype) => {
            rd = itype.rd() as usize;
            rv.regs[rd] = rv.regs[itype.rs1() as usize] ^ (itype.imm_s_ext() as u32);
        }
        Instruction::Srai(shift_type) => {
            rd = shift_type.rd() as usize;
            rv.regs[rd] = ((shift_type.rs1() as i32) >> (shift_type.shamt() & 0x1f)) as u32;
        }
        Instruction::Srli(shift_type) => {
            rd = shift_type.rd() as usize;
            rv.regs[rd] = shift_type.rs1() >> (shift_type.shamt() & 0x1fu32);
        }
        Instruction::Ori(itype) => {
            rd = itype.rd() as usize;
            rv.regs[rd] = rv.regs[itype.rs1() as usize] | (itype.imm_s_ext() as u32);
        }
        Instruction::Andi(itype) => {
            rd = itype.rd() as usize;
            rv.regs[rd] = rv.regs[itype.rs1() as usize] & (itype.imm_s_ext() as u32);
        }
        _ => panic!("invalid instruction"),
    }
    rv.PC += 4;
    if rv_reg_zero == rd as u8 {
        rv.regs[0] = 0;
    }
    true
}

fn op_auipc(rv: &mut RiscvCore, inst: Instruction) -> bool {
    let mut rd = 0;
    match inst {
        Instruction::Auipc(utype) => {
            rd = utype.rd();
            rv.regs[utype.rd() as usize] = rv.PC + utype.imm();
        }
        _ => panic!("invalid instruction"),
    }
    rv.PC += 4;
    if rv_reg_zero == rd as u8 {
        rv.regs[0] = 0;
    }
    true
}

fn op_store(rv: &mut RiscvCore, inst: Instruction) -> bool {
    match inst {
        Instruction::Sb(stype) => {
            let addr = ((stype.rs1() as i32) + stype.imm_s_ext()) as usize;
            let data = rv.regs[stype.rs2() as usize];
            rv.mem.lock().unwrap().write_byte(addr, data as RiscvByte);
        }
        Instruction::Sh(stype) => {
            let addr = ((stype.rs1() as i32) + stype.imm_s_ext()) as usize;
            let data = rv.regs[stype.rs2() as usize];
            rv.mem.lock().unwrap().write_half(addr, data as RiscvHalf);
        }
        Instruction::Sw(stype) => {
            let addr = (rv.regs[rv_reg_sp as usize] as i32 + stype.imm_s_ext()) as usize;
            let data = rv.regs[stype.rs2() as usize];
            rv.mem.lock().unwrap().write_word(addr, data as RiscvWord);
            log::debug!(
                "rs={} val={} addr=0x{:x} sp={} imm={}",
                stype.rs2(),
                data,
                addr,
                rv.regs[rv_reg_sp as usize] as i32,
                stype.imm_s_ext()
            );
        }
        _ => panic!("invalid instruction"),
    }
    rv.PC += 4;
    true
}

fn op_operate_reg(rv: &mut RiscvCore, inst: Instruction) -> bool {
    let mut rd;
    match inst {
        Instruction::Add(rtype) => {
            rd = rtype.rd() as usize;
            let rs1 = rtype.rs1() as usize;
            let rs2 = rtype.rs2() as usize;
            rv.regs[rd] = (rv.regs[rs1] as i32 + rv.regs[rs2] as i32) as u32;
        }
        Instruction::Sll(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = (rtype.rs1() << rtype.rs2() & 0x1f) as u32;
        }
        Instruction::Slt(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = if (rtype.rs1() as i32) < (rtype.rs2() as i32) {
                1
            } else {
                0
            };
        }
        Instruction::Sltu(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = if rtype.rs1() < rtype.rs2() { 1 } else { 0 };
        }
        Instruction::Xor(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = rtype.rs1() ^ rtype.rs2();
        }
        Instruction::Srl(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = (rtype.rs1() >> rtype.rs2() & 0x1f) as u32;
        }
        Instruction::Or(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = rtype.rs1() | rtype.rs2();
        }
        Instruction::And(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = rtype.rs1() & rtype.rs2();
        }
        Instruction::Sub(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = (rtype.rs1() as i32 - rtype.rs2() as i32) as u32;
        }
        Instruction::Sra(rtype) => {
            rd = rtype.rd() as usize;
            rv.regs[rd] = ((rtype.rs1() as i32) >> rtype.rs2() & 0x1f) as u32;
        }
        _ => panic!("invalid instruction"),
    }
    rv.PC += 4;
    if rv_reg_zero == rd as u8 {
        rv.regs[rv_reg_zero as usize] = 0;
    }
    true
}

fn op_lui(rv: &mut RiscvCore, inst: Instruction) -> bool {
    let mut rd = 0;
    match inst {
        Instruction::Lui(utype) => {
            rd = utype.rd();
            rv.regs[utype.rd() as usize] = utype.imm();
        }
        _ => panic!("invalid instruction"),
    }
    rv.PC += 4;
    if rv_reg_zero == rd as u8 {
        rv.regs[0] = 0;
    }
    true
}

fn op_branch(rv: &mut RiscvCore, inst: Instruction) -> bool {
    let mut imm = 0;
    let mut taken = false;
    match inst {
        Instruction::Beq(btype) => {
            imm = btype.imm_s_ext();
            taken = rv.regs[btype.rs1() as usize] == rv.regs[btype.rs1() as usize];
        }
        Instruction::Bne(btype) => {
            imm = btype.imm_s_ext();
            taken = rv.regs[btype.rs1() as usize] != rv.regs[btype.rs1() as usize];
        }
        Instruction::Blt(btype) => {
            imm = btype.imm_s_ext();
            taken = (rv.regs[btype.rs1() as usize] as i32) < (rv.regs[btype.rs1() as usize] as i32);
        }
        Instruction::Bge(btype) => {
            imm = btype.imm_s_ext();
            taken =
                (rv.regs[btype.rs1() as usize] as i32) >= (rv.regs[btype.rs1() as usize] as i32);
        }
        Instruction::Bltu(btype) => {
            imm = btype.imm_s_ext();
            taken = rv.regs[btype.rs1() as usize] < rv.regs[btype.rs1() as usize];
        }
        Instruction::Bgeu(btype) => {
            imm = btype.imm_s_ext();
            log::debug!("bgeu imm={}", imm);
            taken = rv.regs[btype.rs1() as usize] >= rv.regs[btype.rs1() as usize];
        }
        _ => panic!("invalid instruction"),
    }
    if taken {
        let pc = rv.PC as i64 + imm as i64;
        assert!(pc & 0x3 == 0); // 4字节对齐
        rv.PC = pc as u32;
    } else {
        rv.PC += 4;
    }
    true
}

fn op_jalr(rv: &mut RiscvCore, inst: Instruction) -> bool {
    match inst {
        Instruction::Jalr(itype) => {
            let rd = itype.rd();
            let ra = rv.PC + 4;
            rv.PC = ((rv.regs[itype.rs1() as usize] as i32 + itype.imm_s_ext()) as u32) & !1u32;
            if rv_reg_zero != rd as u8 {
                rv.regs[rd as usize] = ra;
            }
            log::debug!(
                "ra={} pc=0x{:x} imm={}",
                rv.regs[super::consts::rv_reg_a0 as usize],
                rv.PC,
                itype.imm_s_ext()
            );
            assert!(rv.PC & 0x3 == 0);
        }
        _ => panic!("invalid instruction"),
    }
    true
}

fn op_jal(rv: &mut RiscvCore, inst: Instruction) -> bool {
    match inst {
        Instruction::Jal(jtype) => {
            let rd = jtype.rd();
            let ra = rv.PC + 4;
            log::debug!("pc={:x}, imm={} rd={}", rv.PC, jtype.imm_s_ext(), rd);
            // 计算跳转地址
            rv.PC = (rv.PC as i32 + jtype.imm_s_ext()) as u32;
            // 设置ra
            if rv_reg_zero != rd as u8 {
                rv.regs[rd as usize] = ra;
            }
            assert!(rv.PC & 0x3 == 0);
        }
        _ => panic!("invalid instruction"),
    }
    true
}

// opcode handler type
pub type OpcodeHanlder = fn(&mut RiscvCore, Instruction) -> bool;

// opcode dispatch table
pub const opcode_handler: [Option<OpcodeHanlder>; 32] = [
    Some(op_load), // 00 000
    None,
    None,
    None,
    Some(op_operate_imm),
    Some(op_auipc),
    None,
    None,
    Some(op_store), // 01 000
    None,
    None,
    None,
    Some(op_operate_reg),
    Some(op_lui),
    None,
    None,
    None, // 10 000
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(op_branch), // 11 000
    Some(op_jalr),
    None,
    Some(op_jal),
    None,
    None,
    None,
    None,
];

fn get_opcode(inst: &Instruction) -> u32 {
    match inst {
        Instruction::Lui(utype) | Instruction::Auipc(utype) => {
            return utype.0;
        }
        Instruction::Jal(jtype) => {
            return jtype.0;
        }
        Instruction::Jalr(itype) => {
            return itype.0;
        }
        Instruction::Beq(btype)
        | Instruction::Bne(btype)
        | Instruction::Blt(btype)
        | Instruction::Bge(btype)
        | Instruction::Bltu(btype)
        | Instruction::Bgeu(btype) => {
            return btype.0;
        }
        Instruction::Lb(itype)
        | Instruction::Lh(itype)
        | Instruction::Lw(itype)
        | Instruction::Lbu(itype)
        | Instruction::Lhu(itype)
        | Instruction::Lwu(itype)
        | Instruction::Ld(itype) => {
            return itype.0;
        }
        Instruction::Sb(stype)
        | Instruction::Sh(stype)
        | Instruction::Sw(stype)
        | Instruction::Sd(stype) => {
            return stype.0;
        }
        Instruction::Addi(itype)
        | Instruction::Slti(itype)
        | Instruction::Sltiu(itype)
        | Instruction::Xori(itype)
        | Instruction::Ori(itype)
        | Instruction::Andi(itype) => {
            return itype.0;
        }
        Instruction::Slli(shift_type)
        | Instruction::Srli(shift_type)
        | Instruction::Srai(shift_type) => {
            return shift_type.0;
        }
        Instruction::Add(rtype)
        | Instruction::Sub(rtype)
        | Instruction::Sll(rtype)
        | Instruction::Slt(rtype)
        | Instruction::Sltu(rtype)
        | Instruction::Xor(rtype)
        | Instruction::Srl(rtype)
        | Instruction::Sra(rtype)
        | Instruction::Or(rtype)
        | Instruction::And(rtype)
        | Instruction::Mul(rtype)
        | Instruction::Mulh(rtype)
        | Instruction::Mulhsu(rtype)
        | Instruction::Mulhu(rtype)
        | Instruction::Div(rtype)
        | Instruction::Divu(rtype)
        | Instruction::Rem(rtype)
        | Instruction::Remu(rtype) => {
            return rtype.0;
        }
        Instruction::Fence(fence_type) => {
            return fence_type.0;
        }
        Instruction::FenceI => {
            return 0b000000000000_00000_001_00000_0001111; // fencei
        }
        Instruction::Ecall => {
            return 0b000000000000_00000_001_00000_1110011;
        }
        Instruction::Ebreak => {
            return 0b000000000001_00000_001_00000_1110011;
        }
        Instruction::Uret => {
            return 0b0000000_00010_00000_000_00000_1110011;
        }
        Instruction::Sret => {
            return 0b0001000_00010_00000_000_00000_1110011;
        }
        Instruction::Mret => {
            return 0b0011000_00010_00000_000_00000_1110011;
        }
        Instruction::Wfi => {
            return 0b0001000_00101_00000_000_00000_1110011;
        }
        Instruction::SfenceVma(rtype) => {
            return rtype.0;
        }
        Instruction::Csrrw(csr_type)
        | Instruction::Csrrs(csr_type)
        | Instruction::Csrrc(csr_type) => {
            return csr_type.0;
        }
        Instruction::Csrrwi(csri_type)
        | Instruction::Csrrsi(csri_type)
        | Instruction::Csrrci(csri_type) => {
            return csri_type.0;
        }
        Instruction::Addiw(itype) => {
            return itype.0;
        }
        Instruction::Slliw(shift_type)
        | Instruction::Srliw(shift_type)
        | Instruction::Sraiw(shift_type) => {
            return shift_type.0;
        }
        Instruction::Addw(rtype)
        | Instruction::Subw(rtype)
        | Instruction::Sllw(rtype)
        | Instruction::Srlw(rtype)
        | Instruction::Sraw(rtype)
        | Instruction::Mulw(rtype)
        | Instruction::Divw(rtype)
        | Instruction::Divuw(rtype)
        | Instruction::Remw(rtype)
        | Instruction::Remuw(rtype) => {
            return rtype.0;
        }
        Instruction::Illegal => {
            panic!("illegal instruction");
        }
        _ => {
            panic!("unknown instruction");
        }
    }
}

const INST_6_2: u32 = 0b00000000000000000000000001111100;
pub fn rv_step(rv: &mut RiscvCore, step_cycles: usize) {
    for i in 0..step_cycles {
        let pc = rv.PC;
        let (raw_inst, inst) = rv.mem.lock().unwrap().read_inst(pc as usize).unwrap();
        println!("idx={} pc=0x{:x} inst={:?}", i, pc, inst);
        let index = ((raw_inst & INST_6_2) >> 2) as usize;
        let op = opcode_handler[index];
        assert!(op.is_some());
        assert!(op.unwrap()(rv, inst));
    }
}

// 1_1111010010_1_11111111_000001101111
// 1_11111111_1_1111010010_0
// 11111111111111111111111110100100
