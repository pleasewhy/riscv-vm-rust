pub struct Chunk {
    data: [u8; 0x10000],
}

pub struct Memory {
    data: [Box<Chunk>; 0x10000],
}
