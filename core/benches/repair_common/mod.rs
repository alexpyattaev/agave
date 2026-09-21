//! Shared fixture for the repair serve-path benches.
use {
    solana_clock::Slot,
    solana_ledger::{
        blockstore::{Blockstore, make_many_slot_entries},
        get_tmp_ledger_path_auto_delete,
        shred::Nonce,
    },
    std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    },
    tempfile::TempDir,
};

pub const FIRST_SLOT: Slot = 1;
pub const NUM_SLOTS: u64 = 32;
pub const ENTRIES_PER_SLOT: u64 = 64;
pub const NONCE: Nonce = 42;

pub struct Fixture {
    pub blockstore: Arc<Blockstore>,
    /// Number of data shreds stored for every slot in the fixture.
    pub shreds_per_slot: u64,
    /// Payload of a single data shred, for benches that skip the blockstore.
    pub shred_payload: Vec<u8>,
    pub dest: SocketAddr,
    _ledger_path: TempDir,
}

impl Fixture {
    /// Youngest slot in the fixture, i.e. the one an orphan request walks back from.
    pub fn last_slot(&self) -> Slot {
        FIRST_SLOT + NUM_SLOTS - 1
    }
}

pub fn fixture() -> Fixture {
    let ledger_path = get_tmp_ledger_path_auto_delete!();
    let blockstore =
        Arc::new(Blockstore::open(ledger_path.path()).expect("failed to open bench blockstore"));
    let (shreds, _entries) = make_many_slot_entries(FIRST_SLOT, NUM_SLOTS, ENTRIES_PER_SLOT);
    let shreds_per_slot = shreds
        .iter()
        .filter(|shred| shred.slot() == FIRST_SLOT)
        .count() as u64;
    assert!(
        shreds_per_slot > 0,
        "fixture must store at least one data shred per slot"
    );
    let shred_payload = shreds
        .first()
        .expect("fixture must produce shreds")
        .payload()
        .to_vec();
    blockstore
        .insert_shreds(shreds, false)
        .expect("failed to populate bench blockstore");

    Fixture {
        blockstore,
        shreds_per_slot,
        shred_payload,
        dest: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        _ledger_path: ledger_path,
    }
}
