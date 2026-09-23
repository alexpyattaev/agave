//! The only wire-format code in this crate.
//!
//! A request is written raw: the requester writes at most [`MAX_REQUEST_BYTES`]
//! and finishes its side of the stream.
//!
//! A response is a sequence of frames, each a little-endian `u16` length
//! followed by that many payload bytes, terminated by the stream FIN. `u16`
//! because a repair response never exceeds one packet; the implementation this
//! replaces spent a bincode fixint `u64` on the same job.
use {
    crate::{
        MAX_RESPONSE_FRAME_BYTES, MAX_RESPONSES_PER_REQUEST, RESPONSE_LENGTH_PREFIX_BYTES,
        error::FramingError,
    },
    bytes::{BufMut, Bytes, BytesMut},
    solana_packet::PACKET_DATA_SIZE,
};

/// Largest response we will read off a stream that expects `num_frames` frames.
pub(crate) fn max_response_bytes(num_frames: usize) -> usize {
    num_frames
        .min(MAX_RESPONSES_PER_REQUEST)
        .saturating_mul(MAX_RESPONSE_FRAME_BYTES)
}

/// Interleave length prefixes with `payloads` for a single `write_all_chunks`.
///
/// Over-long or empty payloads are dropped rather than reported: they can only
/// come from our own serve path, and shipping a frame we know the peer must
/// reject is worse than shipping one response fewer.
pub(crate) fn encode_responses(payloads: &[Bytes]) -> Vec<Bytes> {
    let payloads = payloads
        .iter()
        .filter(|payload| (1..=PACKET_DATA_SIZE).contains(&payload.len()))
        .take(MAX_RESPONSES_PER_REQUEST);
    // One allocation holds every length prefix; each frame header is a slice of it.
    let mut headers =
        BytesMut::with_capacity(MAX_RESPONSES_PER_REQUEST * RESPONSE_LENGTH_PREFIX_BYTES);
    let mut bodies = Vec::with_capacity(MAX_RESPONSES_PER_REQUEST);
    for payload in payloads {
        headers.put_u16_le(payload.len() as u16);
        bodies.push(payload.clone());
    }
    let headers = headers.freeze();
    let mut chunks = Vec::with_capacity(bodies.len().saturating_mul(2));
    for (i, body) in bodies.into_iter().enumerate() {
        let offset = i.saturating_mul(RESPONSE_LENGTH_PREFIX_BYTES);
        chunks.push(headers.slice(offset..offset.saturating_add(RESPONSE_LENGTH_PREFIX_BYTES)));
        chunks.push(body);
    }
    chunks
}

/// Split a complete response body into its frames.
///
/// Every byte of `buf` is peer-controlled: this function must reject rather
/// than assert, and must never panic on any input.
pub(crate) fn decode_responses(buf: Bytes, max_frames: usize) -> Result<Vec<Bytes>, FramingError> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let header_end = offset.saturating_add(RESPONSE_LENGTH_PREFIX_BYTES);
        let Some(header) = buf.get(offset..header_end) else {
            return Err(FramingError::TruncatedHeader);
        };
        let declared = u16::from_le_bytes([header[0], header[1]]) as usize;
        if declared == 0 {
            return Err(FramingError::EmptyFrame);
        }
        if declared > PACKET_DATA_SIZE {
            return Err(FramingError::FrameTooLarge(declared));
        }
        let body_end = header_end.saturating_add(declared);
        if body_end > buf.len() {
            return Err(FramingError::TruncatedBody {
                declared,
                available: buf.len().saturating_sub(header_end),
            });
        }
        if frames.len() >= max_frames.min(MAX_RESPONSES_PER_REQUEST) {
            return Err(FramingError::TooManyFrames(max_frames));
        }
        frames.push(buf.slice(header_end..body_end));
        offset = body_end;
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use {super::*, std::iter::repeat_with};

    fn concat(chunks: &[Bytes]) -> Bytes {
        let mut out = BytesMut::new();
        for chunk in chunks {
            out.extend_from_slice(chunk);
        }
        out.freeze()
    }

    fn payload(len: usize, fill: u8) -> Bytes {
        Bytes::from(vec![fill; len])
    }

    #[test]
    fn round_trip_at_every_supported_frame_count() {
        for count in 0..=MAX_RESPONSES_PER_REQUEST {
            let payloads: Vec<_> = (0..count).map(|i| payload(1 + i, i as u8)).collect();
            let encoded = concat(&encode_responses(&payloads));
            let decoded = decode_responses(encoded, MAX_RESPONSES_PER_REQUEST)
                .expect("our own encoding must decode");
            assert_eq!(decoded, payloads, "round trip lost data at {count} frames");
        }
    }

    #[test]
    fn round_trip_at_max_payload_size() {
        let payloads = vec![payload(PACKET_DATA_SIZE, 0xab)];
        let encoded = concat(&encode_responses(&payloads));
        assert_eq!(
            encoded.len(),
            MAX_RESPONSE_FRAME_BYTES,
            "a full-size frame must be exactly one packet plus its prefix"
        );
        let decoded = decode_responses(encoded, 1).expect("full-size frame must decode");
        assert_eq!(decoded, payloads);
    }

    #[test]
    fn rejects_malformed_frames() {
        let truncated_header = Bytes::from_static(&[7]);
        assert_eq!(
            decode_responses(truncated_header, 1),
            Err(FramingError::TruncatedHeader)
        );

        let truncated_body = Bytes::from_static(&[4, 0, 1, 2]);
        assert_eq!(
            decode_responses(truncated_body, 1),
            Err(FramingError::TruncatedBody {
                declared: 4,
                available: 2
            })
        );

        let zero_length = Bytes::from_static(&[0, 0]);
        assert_eq!(
            decode_responses(zero_length, 1),
            Err(FramingError::EmptyFrame)
        );

        let mut over_length = BytesMut::new();
        over_length.put_u16_le(PACKET_DATA_SIZE as u16 + 1);
        over_length.extend_from_slice(&vec![0u8; PACKET_DATA_SIZE + 1]);
        assert_eq!(
            decode_responses(over_length.freeze(), 1),
            Err(FramingError::FrameTooLarge(PACKET_DATA_SIZE + 1))
        );

        let two_frames = concat(&encode_responses(&[payload(4, 1), payload(4, 2)]));
        assert_eq!(
            decode_responses(two_frames, 1),
            Err(FramingError::TooManyFrames(1))
        );
    }

    /// Nothing a peer can put on the wire may panic the decoder.
    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            // xorshift64: no rand dependency needed for a smoke loop.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..10_000 {
            let len = (next() % 64) as usize;
            let bytes: Vec<u8> = repeat_with(|| (next() & 0xff) as u8).take(len).collect();
            let _ = decode_responses(Bytes::from(bytes), MAX_RESPONSES_PER_REQUEST);
        }
    }

    #[test]
    fn max_response_bytes_is_clamped() {
        assert_eq!(max_response_bytes(1), MAX_RESPONSE_FRAME_BYTES);
        assert_eq!(
            max_response_bytes(usize::MAX),
            MAX_RESPONSES_PER_REQUEST * MAX_RESPONSE_FRAME_BYTES,
            "a peer-supplied frame count must not size an unbounded read"
        );
    }
}
