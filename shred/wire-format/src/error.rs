use {
    crate::shred_variant::{ShredKind, ShredVariant},
    thiserror::Error,
};

/// What can go wrong while parsing raw bytes as a shred.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("shred is {len} bytes, expected at least {expected}")]
    TooShort { len: usize, expected: usize },
    #[error(transparent)]
    Read(#[from] wincode::ReadError),
}

/// What can go wrong while writing a shred into a buffer.
#[derive(Debug, Error)]
pub enum WriteError {
    #[error("expected a {expected:?} shred, got {found:?}")]
    UnexpectedKind {
        expected: ShredKind,
        found: ShredKind,
    },
    #[error("buffer is {len} bytes, expected {expected}")]
    InvalidPayloadSize { len: usize, expected: usize },
    /// The header's variant differs from the one the buffer layout was chosen for.
    #[error("header variant {found:?} does not match buffer variant {expected:?}")]
    VariantMismatch {
        expected: ShredVariant,
        found: ShredVariant,
    },
    #[error(transparent)]
    Write(#[from] wincode::WriteError),
}
