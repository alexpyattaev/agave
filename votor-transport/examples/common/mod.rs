//! Shared helpers for the votor-transport benchmark harness.
//!
//! Each example includes this module separately, so items only one of them
//! needs would otherwise read as dead code.
#![allow(dead_code)]

use solana_keypair::Keypair;

/// Matches `QUIC_CONTROL_TRAFFIC_BUFFER_SIZE` in `solana_gossip::node`.
pub const QUIC_CONTROL_TRAFFIC_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Per-peer datagram rate, offered by the generator and admitted by the server.
pub const DATAGRAMS_PER_SECOND_PER_PEER: usize = 50;

/// Deterministic keypair for load-generator client `index`.
///
/// Server and load generator run as separate processes and must agree on the
/// peer set without exchanging keys, so both derive it from the index alone.
pub fn client_keypair(index: usize) -> Keypair {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8] = 0xC1;
    Keypair::new_from_array(seed)
}

/// Deterministic server keypair, distinct from every [`client_keypair`].
pub fn server_keypair() -> Keypair {
    let mut seed = [0u8; 32];
    seed[8] = 0x5E;
    Keypair::new_from_array(seed)
}
