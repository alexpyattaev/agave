#![cfg(feature = "agave-unstable-api")]
//! The Solana shred wire format.
//!
//! Section boundaries of all four wire layouts and the header fields, derived from the wincode
//! schemas of the headers, plus [`ShredViewMut`](view::ShredViewMut) to write them in place.

pub mod constants;
pub mod error;
pub mod headers;
pub mod kind;
pub mod shred_variant;
pub mod view;
