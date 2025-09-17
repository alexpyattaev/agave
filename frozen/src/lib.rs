#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![deny(missing_docs)]
//! amazing

use serde::Serialize;

#[cfg_attr(feature = "frozen-abi", macro_use)]
#[cfg(feature = "frozen-abi")]
extern crate solana_frozen_abi_macro;

/// CrdsValue that is replicated across the cluster
#[cfg_attr(
    feature = "frozen-abi",
    derive(AbiExample),
    frozen_abi(digest = "DogHQiAMgESKfx4hhwMDVQiukebrWqmMeki4WSRHTTWH")
)]
#[derive(Serialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Value {
    signature: u8,
    data: u16,
    things: Vec<u8>,
    hash: (u16, u16),
}

#[cfg(test)]
mod tests {
    use crate::Value;
    #[test]
    fn bla() {
        let val = Value::default();
        let v = bincode::serialize(&val).unwrap();
        println!("Hello, world! {v:?}");
    }
}
