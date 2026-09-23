use {
    quinn::{ConnectError, ConnectionError, ReadToEndError, WriteError},
    solana_pubkey::Pubkey,
    std::{io, net::SocketAddr},
    thiserror::Error,
};

/// Application close codes and matching reason strings.
///
/// Numeric codes are part of the wire format - adding a new one is fine,
/// changing the value of an existing one is a breaking protocol change.
pub(crate) mod close_codes {
    use quinn::{Connection, VarInt};

    pub(crate) struct Spec {
        pub code: VarInt,
        pub reason: &'static [u8],
    }

    impl Spec {
        /// Close `conn` with this spec's code/reason pair.
        pub fn close(&self, conn: &Connection) {
            conn.close(self.code, self.reason);
        }
    }

    pub(crate) const NORMAL_CLOSE: Spec = Spec {
        code: VarInt::from_u32(0),
        reason: b"NORMAL_CLOSE",
    };

    pub(crate) const PEER_MOVED: Spec = Spec {
        code: VarInt::from_u32(1),
        reason: b"PEER_MOVED",
    };

    pub(crate) const INVALID_IDENTITY: Spec = Spec {
        code: VarInt::from_u32(2),
        reason: b"INVALID_IDENTITY",
    };

    pub(crate) const NOT_ADMITTED: Spec = Spec {
        code: VarInt::from_u32(3),
        reason: b"NOT_ADMITTED",
    };

    pub(crate) const BANNED: Spec = Spec {
        code: VarInt::from_u32(4),
        reason: b"BANNED",
    };

    pub(crate) const TOO_MANY_CONNECTIONS: Spec = Spec {
        code: VarInt::from_u32(5),
        reason: b"TOO_MANY_CONNECTIONS",
    };

    pub(crate) const IDENTITY_CHANGED: Spec = Spec {
        code: VarInt::from_u32(6),
        reason: b"IDENTITY_CHANGED",
    };

    /// The same pubkey dialed us again: the older connection is retired so a
    /// restarting peer is not locked out by its own stale connection.
    pub(crate) const REPLACED: Spec = Spec {
        code: VarInt::from_u32(7),
        reason: b"REPLACED",
    };

    /// Peer violated the stream framing (over-long frame, too many frames).
    pub(crate) const PROTOCOL_VIOLATION: Spec = Spec {
        code: VarInt::from_u32(8),
        reason: b"PROTOCOL_VIOLATION",
    };
    // When adding a new close code, make sure to also capture it
    // in test_close_codes_are_frozen.
}

/// Error codes used to reset an individual stream. Like close codes these are
/// wire format, but they are advisory: nothing in the protocol branches on them.
pub(crate) mod stream_codes {
    use quinn::VarInt;

    /// Request could not be read within the deadline, or was over-long.
    pub(crate) const BAD_REQUEST: VarInt = VarInt::from_u32(1);
    /// We have nowhere to put this request right now.
    pub(crate) const OVERLOADED: VarInt = VarInt::from_u32(2);
}

/// Response framing errors. Every byte here is peer-controlled, so this must
/// never be a `debug_assert!`.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum FramingError {
    #[error("response frame header is truncated")]
    TruncatedHeader,

    #[error("response frame body is truncated: {declared} declared, {available} available")]
    TruncatedBody { declared: usize, available: usize },

    #[error("response frame declares zero length")]
    EmptyFrame,

    #[error("response frame of {0} bytes exceeds one packet")]
    FrameTooLarge(usize),

    #[error("response carries more than the {0} frames the request allows")]
    TooManyFrames(usize),
}

/// All errors observed by the transport.
/// Fed into the stats via `record_client_error` and `record_server_error`.
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Connect(#[from] ConnectError),

    #[error(transparent)]
    Connection(#[from] ConnectionError),

    #[error(transparent)]
    Write(#[from] WriteError),

    #[error(transparent)]
    Read(#[from] ReadToEndError),

    #[error(transparent)]
    Framing(#[from] FramingError),

    /// TLS handshake succeeded but the peer cert did not yield a recoverable
    /// solana ed25519 pubkey. The connection is closed by the caller.
    #[error("invalid identity from {0:?}")]
    InvalidIdentity(SocketAddr),

    /// We dialed `expected` and the server attested to being someone else.
    #[error("dialed {expected} at {address} but it attested {attested}")]
    WrongIdentity {
        expected: Pubkey,
        attested: Pubkey,
        address: SocketAddr,
    },

    /// Peer pubkey is not known to gossip, so we will not serve it.
    #[error("peer {0} is not known to gossip")]
    NotAdmitted(Pubkey),

    /// Peer pubkey is currently banned.
    #[error("peer {0} is banned")]
    Banned(Pubkey),

    /// Inbound refused at a capacity limit: the connection table is full.
    #[error("too many connections")]
    TooManyConnections,

    /// The exchange did not complete within its deadline.
    #[error("exchange with {0} timed out")]
    Timeout(Pubkey),

    /// `quinn::Endpoint::new` failed. Construction-time only.
    #[error(transparent)]
    Endpoint(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use {super::close_codes, quinn::VarInt};

    /// Close codes are wire format: changing an existing value is a breaking
    /// change. Pin every code/reason pair so an accidental edit fails here
    /// instead of silently breaking interop.
    #[test]
    fn test_close_codes_are_frozen() {
        let pinned: [(&close_codes::Spec, u32, &[u8]); 9] = [
            (&close_codes::NORMAL_CLOSE, 0, b"NORMAL_CLOSE"),
            (&close_codes::PEER_MOVED, 1, b"PEER_MOVED"),
            (&close_codes::INVALID_IDENTITY, 2, b"INVALID_IDENTITY"),
            (&close_codes::NOT_ADMITTED, 3, b"NOT_ADMITTED"),
            (&close_codes::BANNED, 4, b"BANNED"),
            (
                &close_codes::TOO_MANY_CONNECTIONS,
                5,
                b"TOO_MANY_CONNECTIONS",
            ),
            (&close_codes::IDENTITY_CHANGED, 6, b"IDENTITY_CHANGED"),
            (&close_codes::REPLACED, 7, b"REPLACED"),
            (&close_codes::PROTOCOL_VIOLATION, 8, b"PROTOCOL_VIOLATION"),
        ];
        for (spec, code, reason) in pinned {
            assert_eq!(
                spec.code,
                VarInt::from_u32(code),
                "close code value changed: this is a breaking protocol change"
            );
            assert_eq!(
                spec.reason, reason,
                "close reason changed: this is a breaking protocol change"
            );
        }
    }
}
