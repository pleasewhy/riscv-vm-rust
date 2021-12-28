pub mod memory;
pub mod state;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeError {
    /// Instruction Error.
    InstructionError,
    /// Memory Error.
    MemoryError,
}
