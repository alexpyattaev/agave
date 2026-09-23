use {
    solana_gossip::{cluster_info::ClusterInfoError, contact_info},
    thiserror::Error,
};

#[derive(Error, Debug)]
pub enum RepairVerifyError {
    #[error("IdMismatch")]
    IdMismatch,
    #[error("Malformed")]
    Malformed,
    /// The QUIC-attested identity of the sender disagrees with the pubkey the
    /// request is signed by. Rejecting is what replaces ping/pong on that path:
    /// the signature covers neither the source address nor the transport, so a
    /// captured request is otherwise replayable for the whole signing window.
    #[error("PubkeyMismatch")]
    PubkeyMismatch,
    #[error("SelfRepair")]
    SelfRepair,
    #[error("SigVerify")]
    SigVerify,
    #[error("TimeSkew")]
    TimeSkew,
    #[error("Unsigned")]
    Unsigned,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    ClusterInfo(#[from] ClusterInfoError),
    #[error(transparent)]
    InvalidContactInfo(#[from] contact_info::Error),
    #[error(transparent)]
    RepairVerify(#[from] RepairVerifyError),
    #[error("Send Error")]
    SendError,
    #[error(transparent)]
    Serialize(#[from] wincode::WriteError),
    #[error(transparent)]
    Deserialize(#[from] wincode::ReadError),
    #[error(transparent)]
    WeightedIndex(#[from] rand::distr::weighted::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
