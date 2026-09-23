//! Transport tuning constants for a repair workload.
use {
    crate::{
        HANDSHAKE_DRAIN_RATE, MAX_CONCURRENT_STREAMS_PER_PEER, MAX_INCOMING_DELAY,
        MAX_REQUEST_BYTES, MAX_RESPONSE_FRAME_BYTES, MAX_RESPONSES_PER_REQUEST, REPAIR_ALPN,
    },
    quinn::{
        ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt,
        crypto::rustls::{QuicClientConfig, QuicServerConfig},
    },
    solana_keypair::Keypair,
    solana_tls_utils::{
        new_dummy_x509_certificate, tls_client_config_builder, tls_server_config_builder,
    },
    std::{sync::Arc, time::Duration},
};

/// Close connections after this much time without feedback from the peer.
/// Repair to a given peer is bursty, so this is long enough that a peer we
/// repair from repeatedly does not pay a handshake every time.
pub(crate) const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// QUIC keep-alive heartbeat, used by the requester only: the server has no
/// reason to keep a connection alive that its peer has stopped using.
/// Must be << [`MAX_IDLE_TIMEOUT`].
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(4);

/// Bytes a peer may have in flight to us across all of its streams.
const RECEIVE_WINDOW: u32 =
    MAX_CONCURRENT_STREAMS_PER_PEER.saturating_mul(MAX_RESPONSE_FRAME_BYTES as u32);

/// Max number of connection attempts quinn buffers *per endpoint* before it
/// starts dropping Initials outright.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn compute_max_incoming(num_endpoints: usize) -> usize {
    debug_assert!(num_endpoints > 0, "an endpoint needs at least one socket");
    let per_endpoint_rate = HANDSHAKE_DRAIN_RATE / num_endpoints;
    (per_endpoint_rate * MAX_INCOMING_DELAY.as_millis() as usize / 1000).max(1)
}

/// Shared transport settings. `max_streams_from_peer` is what the *peer* may
/// open towards us: the server accepts request streams, the requester accepts
/// none, which is how the one-directional stream contract is enforced by quinn
/// rather than by us closing offenders after the fact.
fn new_transport_config(max_streams_from_peer: u32, keep_alive: bool) -> TransportConfig {
    let max_idle =
        IdleTimeout::try_from(MAX_IDLE_TIMEOUT).expect("MAX_IDLE_TIMEOUT fits IdleTimeout");
    let mut cfg = TransportConfig::default();
    cfg.max_idle_timeout(Some(max_idle))
        .keep_alive_interval(keep_alive.then_some(KEEP_ALIVE_INTERVAL))
        .max_concurrent_bidi_streams(VarInt::from(max_streams_from_peer))
        .max_concurrent_uni_streams(VarInt::from(0u8))
        .receive_window(VarInt::from(RECEIVE_WINDOW))
        // Datagrams are unused; refusing them keeps the surface to streams only.
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .enable_segmentation_offload(false);
    cfg
}

/// Build the rustls + quinn server config.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn new_server_config(keypair: &Keypair, num_endpoints: usize) -> ServerConfig {
    let (cert, key) = new_dummy_x509_certificate(keypair);
    let mut tls = tls_server_config_builder()
        .with_single_cert(vec![cert], key)
        .expect("rustls accepts our self-signed solana cert/key pair");
    tls.alpn_protocols = vec![REPAIR_ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let quic = QuicServerConfig::try_from(tls)
        .expect("TLS 1.3-only config yields an initial cipher suite");
    let mut cfg = ServerConfig::with_crypto(Arc::new(quic));
    let max_incoming = compute_max_incoming(num_endpoints);
    cfg.incoming_buffer_size(MAX_REQUEST_BYTES as u64 * 2);
    cfg.incoming_buffer_size_total(max_incoming as u64 * MAX_REQUEST_BYTES as u64 * 2);
    cfg.max_incoming(max_incoming);
    cfg.retry_token_lifetime(MAX_IDLE_TIMEOUT);
    let mut transport = new_transport_config(MAX_CONCURRENT_STREAMS_PER_PEER, false);
    // A request is one packet, so no peer needs more than that per stream.
    transport.stream_receive_window(VarInt::from(MAX_REQUEST_BYTES as u32));
    cfg.transport_config(Arc::new(transport));
    cfg.migration(false);
    cfg
}

/// Build the rustls + quinn client config.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn new_client_config(keypair: &Keypair) -> ClientConfig {
    let (cert, key) = new_dummy_x509_certificate(keypair);
    let mut tls = tls_client_config_builder()
        .with_client_auth_cert(vec![cert], key)
        .expect("rustls accepts our solana cert/key pair");
    tls.enable_early_data = false;
    tls.alpn_protocols = vec![REPAIR_ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(tls).expect("TLS config should be valid");
    let mut cfg = ClientConfig::new(Arc::new(quic));
    let max_streams_from_server = 0;
    let mut transport = new_transport_config(max_streams_from_server, true);
    transport.stream_receive_window(VarInt::from(
        (MAX_RESPONSES_PER_REQUEST * MAX_RESPONSE_FRAME_BYTES) as u32,
    ));
    cfg.transport_config(Arc::new(transport));
    cfg
}

#[cfg(test)]
mod tests {
    use {
        super::compute_max_incoming,
        crate::{
            HANDSHAKE_DRAIN_RATE, HANDSHAKE_GLOBAL_RATE, HANDSHAKE_WORKERS_PER_ENDPOINT,
            MAX_ENDPOINTS, MAX_INCOMING_DELAY,
        },
    };

    #[test]
    fn max_incoming_splits_across_endpoints() {
        // One endpoint owns the entire drain budget for one full delay window.
        let total_buffered_handshakes = HANDSHAKE_DRAIN_RATE
            .saturating_mul(MAX_INCOMING_DELAY.as_millis() as usize)
            .saturating_div(1000);
        assert_eq!(
            compute_max_incoming(1),
            total_buffered_handshakes,
            "a lone endpoint should buffer MAX_INCOMING_DELAY worth of the HANDSHAKE_DRAIN_RATE \
             drain budget",
        );

        for num_endpoints in 1..=MAX_ENDPOINTS {
            let queue_length = compute_max_incoming(num_endpoints);

            let even_share = total_buffered_handshakes as f32 / num_endpoints as f32;
            assert!(
                (queue_length as f32 - even_share).abs() < 2.0,
                "each of {num_endpoints} should buffer ~{even_share} Initials, got {queue_length}",
            );
            assert!(even_share > 8.0, "sanity");

            let num_accept_loops = num_endpoints.saturating_mul(HANDSHAKE_WORKERS_PER_ENDPOINT);
            let per_loop_rate = HANDSHAKE_GLOBAL_RATE as f64 / num_accept_loops as f64;
            let per_endpoint_rate = per_loop_rate * HANDSHAKE_WORKERS_PER_ENDPOINT as f64;
            let delay_secs = queue_length as f64 / per_endpoint_rate;
            assert!(
                delay_secs <= MAX_INCOMING_DELAY.as_secs_f64(),
                "with {num_endpoints} endpoints a queued attempt waits up to {delay_secs}s, over \
                 the MAX_INCOMING_DELAY budget",
            );
        }
    }
}
