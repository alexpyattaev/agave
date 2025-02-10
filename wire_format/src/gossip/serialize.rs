use {serde::Serialize, solana_gossip::protocol::Protocol};
pub fn parse_gossip(bytes: &[u8]) -> bincode::Result<Protocol> {
    solana_perf::packet::deserialize_from_with_limit(bytes)
}

pub fn serialize_gossip<T: Serialize>(pkt: T) -> Vec<u8> {
    bincode::serialize(&pkt).unwrap()
}
