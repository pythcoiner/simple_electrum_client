use std::fmt::Debug;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Method {
    #[serde(rename = "server.banner")]
    Banner,
    #[serde(rename = "blockchain.block.header")]
    BlockHeader,
    #[serde(rename = "blockchain.block.headers")]
    BlockHeaders,
    #[serde(rename = "blockchain.transaction.broadcast")]
    TransactionBroadcast,
    #[serde(rename = "server.donation_address")]
    Donation,
    #[serde(rename = "blockchain.estimatefee")]
    EstimateFee,
    #[serde(rename = "server.features")]
    Features,
    #[serde(rename = "blockchain.headers.subscribe")]
    HeadersSubscribe,
    #[serde(rename = "mempool.get_fee_histogram")]
    FeeHistogram,
    #[serde(rename = "server.peers.subscribe")]
    ListPeers,
    #[serde(rename = "server.ping")]
    Ping,
    #[serde(rename = "blockchain.relayfee")]
    RelayFee,
    #[serde(rename = "blockchain.scripthash.get_balance")]
    ScriptHashGetBalance,
    #[serde(rename = "blockchain.scripthash.get_history")]
    ScriptHashGetHistory,
    // NOTE: not supported by electrs
    // #[serde(rename = "blockchain.scripthash.get_mempool")]
    // ScriptHashGetMempool,
    #[serde(rename = "blockchain.scripthash.listunspent")]
    ScriptHashListUnspent,
    #[serde(rename = "blockchain.scripthash.subscribe")]
    ScriptHashSubscribe,
    #[serde(rename = "blockchain.scripthash.unsubscribe")]
    ScriptHashUnsubscribe,
    #[serde(rename = "blockchain.transaction.get")]
    TransactionGet,
    #[serde(rename = "blockchain.transaction.get_merkle")]
    TransactionGetMerkle,
    #[serde(rename = "blockchain.transaction.id_from_pos")]
    TransactionFromPosition,
    #[serde(rename = "server.version")]
    Version,
}

impl Debug for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Banner => write!(f, "Banner"),
            Self::BlockHeader => write!(f, "BlockHeader"),
            Self::BlockHeaders => write!(f, "BlockHeaders"),
            Self::TransactionBroadcast => write!(f, "TransactionBroadcast"),
            Self::Donation => write!(f, "Donation"),
            Self::EstimateFee => write!(f, "EstimateFee"),
            Self::Features => write!(f, "Features"),
            Self::HeadersSubscribe => write!(f, "HeadersSubscribe"),
            Self::FeeHistogram => write!(f, "MempoolFeeHistogram"),
            Self::ListPeers => write!(f, "ListPeers"),
            Self::Ping => write!(f, "Ping"),
            Self::RelayFee => write!(f, "RelayFee"),
            Self::ScriptHashGetBalance => write!(f, "ScriptHashGetBalance"),
            Self::ScriptHashGetHistory => write!(f, "ScriptHashGetHistory"),
            Self::ScriptHashListUnspent => write!(f, "ScriptHashListUnspent"),
            Self::ScriptHashSubscribe => write!(f, "ScriptHashSubscribe"),
            Self::ScriptHashUnsubscribe => write!(f, "ScriptHashUnsubscribe"),
            Self::TransactionGet => write!(f, "TransactionGet"),
            Self::TransactionGetMerkle => write!(f, "TransactionGetMerkle"),
            Self::TransactionFromPosition => write!(f, "TransactionFromPosition"),
            Self::Version => write!(f, "Version"),
            // NOTE: not supported by electrs
            // Self::ScriptHashGetMempool => todo!(),
        }
    }
}
