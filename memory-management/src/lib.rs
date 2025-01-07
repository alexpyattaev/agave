#![deny(clippy::arithmetic_side_effects)]
pub mod aligned_memory;

pub mod jemalloc_monitor;
pub mod jemalloc_monitor_metrics;

/// Returns true if `ptr` is aligned to `align`.
pub fn is_memory_aligned(ptr: usize, align: usize) -> bool {
    ptr.checked_rem(align)
        .map(|remainder| remainder == 0)
        .unwrap_or(false)
}
