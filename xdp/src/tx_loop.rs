#![allow(clippy::arithmetic_side_effects)]

use {
    crate::{
        device::{NetworkDevice, QueueId},
        netlink::MacAddress,
        packet::{
            write_eth_header, write_ip_header, write_udp_header, ETH_HEADER_SIZE, IP_HEADER_SIZE,
            UDP_HEADER_SIZE,
        },
        route::Router,
        set_cpu_affinity,
        socket::{Socket, Tx, TxRing},
        umem::{Frame as _, PageAlignedMemory, SliceUmem, SliceUmemFrame, Umem as _},
    },
    caps::{
        CapSet,
        Capability::{CAP_NET_ADMIN, CAP_NET_RAW},
    },
    crossbeam_channel::{Receiver, Sender, TryRecvError},
    libc::{sysconf, _SC_PAGESIZE},
    std::{
        net::{IpAddr, SocketAddr},
        thread,
        time::Duration,
    },
};

pub fn tx_loop<T: AsRef<[u8]>>(
    dev: &NetworkDevice,
    src_port: u16,
    queue_id: QueueId,
    zero_copy: bool,
    cpu_id: usize,
    receiver: Receiver<(Vec<SocketAddr>, T)>,
    drop_sender: Sender<(Vec<SocketAddr>, T)>,
) {
    log::info!(
        "starting xdp loop on {} queue {queue_id:?} cpu {cpu_id}",
        dev.name()
    );

    // each queue is bound to its own CPU core
    set_cpu_affinity([cpu_id]).unwrap();

    let src_mac = dev.mac_addr().unwrap();
    let src_ip = dev.ipv4_addr().unwrap();

    // some drivers require frame_size=page_size
    let frame_size = unsafe { sysconf(_SC_PAGESIZE) } as usize;

    let queue = dev
        .open_queue(queue_id)
        .expect("failed to open queue for AF_XDP socket");
    let rx_size = queue.rx_size();
    let tx_size = queue.tx_size();
    let frame_count = (rx_size + tx_size) * 2;

    // try to allocate huge pages first, then fall back to regular pages
    const HUGE_2MB: usize = 2 * 1024 * 1024;
    let mut memory =
        PageAlignedMemory::alloc_with_page_size(frame_size, frame_count, HUGE_2MB, true)
            .or_else(|_| {
                log::warn!("huge page alloc failed, falling back to regular page size");
                PageAlignedMemory::alloc(frame_size, frame_count)
            })
            .unwrap();
    let umem = SliceUmem::new(&mut memory, frame_size as u32).unwrap();

    // we need NET_ADMIN and NET_RAW for the socket
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::raise(None, CapSet::Effective, cap).unwrap();
    }

    let Ok((mut socket, tx)) = Socket::tx(queue, umem, zero_copy, tx_size * 2, tx_size) else {
        panic!("failed to create AF_XDP socket on queue {queue_id:?}");
    };

    let umem = socket.umem();
    let Tx {
        // this is where we'll queue frames
        ring,
        // this is where we'll get completion events once frames have been picked up by the NIC
        mut completion,
    } = tx;
    let mut ring = ring.unwrap();

    // get the routing table from netlink
    let router = Router::new().expect("failed to create router");

    // we don't need higher caps anymore
    for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
        caps::drop(None, CapSet::Effective, cap).unwrap();
    }

    // How long we sleep waiting to receive shreds from the channel.
    const RECV_TIMEOUT: Duration = Duration::from_nanos(1000);

    const MAX_TIMEOUTS: usize = 500;

    // We try to collect _at least_ BATCH_SIZE packets before queueing into the NIC. This is to
    // avoid introducing too much per-packet overhead and giving the NIC time to complete work
    // before we queue the next chunk of packets.
    const BATCH_SIZE: usize = 64;

    // Local buffer where we store packets before sending themi.
    let mut batched_items = Vec::with_capacity(BATCH_SIZE);

    // How many packets we've batched. This is _not_ batched_items.len(), but item * peers. For
    // example if we have 3 packets to transmit to 2 destination addresses each, we have 6 batched
    // packets.
    let mut batched_packets = 0;

    // With some drivers, or always when we work in SKB mode, we need to explicitly kick the driver
    // once we want the NIC to do something.
    let kick = |ring: &TxRing<SliceUmemFrame<'_>>| {
        if !ring.needs_wakeup() {
            return;
        }

        if let Err(e) = ring.wake() {
            match e.raw_os_error() {
                // these are non-fatal errors
                Some(libc::EBUSY | libc::ENOBUFS | libc::EAGAIN) => {}
                // this can temporarily happen with some drivers when changing
                // settings (eg with ethtool)
                Some(libc::ENETDOWN) => {
                    log::warn!("network interface is down")
                }
                // we should never get here, hopefully the driver recovers?
                _ => {
                    log::error!("network interface driver error: {e:?}");
                }
            }
        }
    };

    let mut timeouts = 0;
    loop {
        match receiver.try_recv() {
            Ok((addrs, payload)) => {
                batched_packets += addrs.len();
                batched_items.push((addrs, payload));
                timeouts = 0;
                if batched_packets < BATCH_SIZE {
                    continue;
                }
            }
            Err(TryRecvError::Empty) => {
                if timeouts < MAX_TIMEOUTS {
                    timeouts += 1;
                    thread::sleep(RECV_TIMEOUT);
                } else {
                    timeouts = 0;
                    // we haven't received anything in a while, kick the driver
                    ring.commit();
                    kick(&ring);
                }
            }
            Err(TryRecvError::Disconnected) => {
                // keep looping until we've flushed all the packets
                if batched_packets == 0 {
                    break;
                }
            }
        };

        // this is the number of packets after which we commit the ring and kick the driver if
        // necessary
        let mut chunk_remaining = BATCH_SIZE.min(batched_packets);

        for (addrs, payload) in batched_items.drain(..) {
            for addr in &addrs {
                // loop until we have space for the next packet
                loop {
                    completion.sync(true);
                    // we haven't written any frames so we only need to sync the consumer position
                    ring.sync(false);

                    // check if any frames were completed
                    while let Some(frame_offset) = completion.read() {
                        umem.release(frame_offset);
                    }

                    if ring.available() > 0 && umem.available() > 0 {
                        // we have a frame and a slot in the ring
                        break;
                    }

                    // queues are full, if NEEDS_WAKEUP is set kick the driver so hopefully it'll
                    // complete some work
                    kick(&ring);
                }

                // at this point we're guaranteed to have a frame to write the next packet into and
                // a slot in the ring to submit it
                let mut frame = umem.reserve().unwrap();
                let IpAddr::V4(dst_ip) = addr.ip() else {
                    panic!("IPv6 not supported");
                };

                let next_hop = router.route(addr.ip()).unwrap();
                // sanity check that the address is routable through our NIC
                if next_hop.if_index != dev.if_index() {
                    log::warn!(
                        "turbine peer {} must be routed through if_index: {} our if_index: {}",
                        addr,
                        next_hop.if_index,
                        dev.if_index()
                    );
                    batched_packets -= 1;
                    umem.release(frame.offset());
                    continue;
                }
                const PACKET_HEADER_SIZE: usize =
                    ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
                let len = payload.as_ref().len();
                frame.set_len(PACKET_HEADER_SIZE + len);
                let packet = umem.map_frame_mut(&frame);

                // write the payload first as it's needed for checksum calculation (if enabled)
                packet[PACKET_HEADER_SIZE..][..len].copy_from_slice(payload.as_ref());

                write_eth_header(
                    packet,
                    &src_mac,
                    // the unwrap case is for loopback interfaces which don't have a mac address
                    &next_hop.mac_addr.unwrap_or(MacAddress([0u8; 6])).0,
                );

                write_ip_header(
                    &mut packet[ETH_HEADER_SIZE..],
                    &src_ip,
                    &dst_ip,
                    (UDP_HEADER_SIZE + len) as u16,
                );

                write_udp_header(
                    &mut packet[ETH_HEADER_SIZE + IP_HEADER_SIZE..],
                    &src_ip,
                    src_port,
                    &dst_ip,
                    addr.port(),
                    len as u16,
                    // don't do checksums
                    false,
                );

                // write the packet into the ring
                ring.write(frame, 0)
                    .map_err(|_| "ring full")
                    // this should never happen as we check for available slots above
                    .expect("failed to write to ring");

                batched_packets -= 1;
                chunk_remaining -= 1;

                // check if it's time to commit the ring and kick the driver
                if chunk_remaining == 0 {
                    chunk_remaining = BATCH_SIZE.min(batched_packets);

                    // commit new frames
                    ring.commit();
                    kick(&ring);
                }
            }
            let _ = drop_sender.try_send((addrs, payload));
        }
        debug_assert_eq!(batched_packets, 0);
    }
    assert_eq!(batched_packets, 0);

    // drain the ring
    while umem.available() < umem.capacity() || ring.available() < ring.capacity() {
        log::debug!(
            "draining xdp ring umem {}/{} ring {}/{}",
            umem.available(),
            umem.capacity(),
            ring.available(),
            ring.capacity()
        );

        completion.sync(true);
        while let Some(frame_offset) = completion.read() {
            umem.release(frame_offset);
        }

        ring.sync(false);
        kick(&ring);
    }
}
