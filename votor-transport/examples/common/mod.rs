//! Shared helpers for the votor-transport benchmark harness.
//!
//! Deliberately dependency-light: argument parsing is hand-rolled so the
//! harness does not pull a CLI crate into `votor-transport`'s dev-dependencies.
//!
//! Each example includes this module separately, so items only one of them
//! needs would otherwise read as dead code.
#![allow(dead_code)]

use {
    solana_keypair::Keypair,
    std::{fmt::Display, str::FromStr},
};

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

/// Minimal `--key value` parser over the process arguments.
pub struct Args(Vec<String>);

impl Args {
    pub fn from_env() -> Self {
        Self(std::env::args().skip(1).collect())
    }

    /// Value of `--name`, or `default` when the flag is absent.
    pub fn get<T>(&self, name: &str, default: T) -> T
    where
        T: FromStr,
        <T as FromStr>::Err: Display,
    {
        match self.0.iter().position(|a| a == &format!("--{name}")) {
            Some(pos) => {
                let raw = self
                    .0
                    .get(pos.saturating_add(1))
                    .unwrap_or_else(|| panic!("--{name} requires a value"));
                raw.parse()
                    .unwrap_or_else(|e| panic!("--{name} value {raw:?} is invalid: {e}"))
            }
            None => default,
        }
    }

    /// Value of a mandatory `--name`.
    pub fn require<T>(&self, name: &str) -> T
    where
        T: FromStr,
        <T as FromStr>::Err: Display,
    {
        let pos = self
            .0
            .iter()
            .position(|a| a == &format!("--{name}"))
            .unwrap_or_else(|| panic!("--{name} is required"));
        let raw = self
            .0
            .get(pos.saturating_add(1))
            .unwrap_or_else(|| panic!("--{name} requires a value"));
        raw.parse()
            .unwrap_or_else(|e| panic!("--{name} value {raw:?} is invalid: {e}"))
    }
}
