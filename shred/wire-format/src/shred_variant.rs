//! The variant byte at offset 64, which selects the shred's kind and layout.

use wincode::{SchemaRead, SchemaWrite};

/// High nibble: kind and resigned flag. Low nibble: Merkle proof entries, fixed at
/// [`MERKLE_PROOF_ENTRIES`](crate::constants::MERKLE_PROOF_ENTRIES):
///
/// ```text
/// 0b0110_0110  0x66  Code
/// 0b0111_0110  0x76  Code, resigned
/// 0b1001_0110  0x96  Data
/// 0b1011_0110  0xb6  Data, resigned
/// ```
///
/// Every other byte is invalid.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
#[repr(u8)]
pub enum ShredVariant {
    #[wincode(tag = 0x66)]
    MerkleCode = 0x66,
    #[wincode(tag = 0x76)]
    MerkleCodeResigned = 0x76,
    #[wincode(tag = 0x96)]
    MerkleData = 0x96,
    #[wincode(tag = 0xb6)]
    MerkleDataResigned = 0xb6,
}

impl ShredVariant {
    #[inline]
    pub const fn data(resigned: bool) -> Self {
        if resigned {
            Self::MerkleDataResigned
        } else {
            Self::MerkleData
        }
    }

    #[inline]
    pub const fn code(resigned: bool) -> Self {
        if resigned {
            Self::MerkleCodeResigned
        } else {
            Self::MerkleCode
        }
    }

    /// Whether a retransmitter signature trails the Merkle proof.
    #[inline]
    pub const fn resigned(self) -> bool {
        matches!(self, Self::MerkleCodeResigned | Self::MerkleDataResigned)
    }

    #[inline]
    pub const fn shred_kind(self) -> ShredKind {
        match self {
            Self::MerkleCode | Self::MerkleCodeResigned => ShredKind::Code,
            Self::MerkleData | Self::MerkleDataResigned => ShredKind::Data,
        }
    }
}

/// Which of the two kinds of shred this is.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ShredKind {
    Data,
    Code,
}
