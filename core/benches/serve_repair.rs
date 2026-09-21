//! Timing benches for the repair serve path.
#![allow(clippy::arithmetic_side_effects)]
#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
use jemallocator::Jemalloc;
use {
    criterion::{Criterion, Throughput, criterion_group, criterion_main},
    repair_common::{FIRST_SLOT, NONCE, fixture},
    solana_core::repair::{
        repair_handler::RepairHandler, repair_response, serve_repair::MAX_ORPHAN_REPAIR_RESPONSES,
        standard_repair_handler::StandardRepairHandler,
    },
    std::hint::black_box,
};

mod repair_common;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn bench_repair_response(c: &mut Criterion) {
    let fixture = fixture();
    c.bench_function("repair_response/packet_from_bytes", |b| {
        b.iter(|| {
            black_box(repair_response::repair_response_packet_from_bytes(
                black_box(&fixture.shred_payload),
                &fixture.dest,
                NONCE,
            ))
        })
    });
}

fn bench_repair_handler(c: &mut Criterion) {
    let fixture = fixture();
    let handler = StandardRepairHandler::new(fixture.blockstore.clone());

    let mut group = c.benchmark_group("repair_handler");
    let mut shred_index = 0;
    group.bench_function("window_request", |b| {
        b.iter(|| {
            shred_index = (shred_index + 1) % fixture.shreds_per_slot;
            black_box(handler.run_window_request(&fixture.dest, FIRST_SLOT, shred_index, NONCE))
        })
    });

    group.throughput(Throughput::Elements(MAX_ORPHAN_REPAIR_RESPONSES as u64));
    group.bench_function("orphan", |b| {
        b.iter(|| {
            black_box(handler.run_orphan(
                &fixture.dest,
                fixture.last_slot(),
                MAX_ORPHAN_REPAIR_RESPONSES,
                NONCE,
            ))
        })
    });
    group.finish();
}

criterion_group!(benches, bench_repair_response, bench_repair_handler);
criterion_main!(benches);
