#![no_std]

pub const FILTER_LEN: u32 = 32;

#[derive(Clone, Copy)]
#[repr(u64)]
pub enum Flags {
    Default = 0,
    OnlyGre = 1,
    StripGre = 2,
}

impl Default for Flags {
    fn default() -> Self {
        Self::Default
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Flags {}

#[cfg(not(feature = "user"))]
pub mod ebpf_helpers;
