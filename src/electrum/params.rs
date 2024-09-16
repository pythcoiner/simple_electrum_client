use super::types::ScriptHash;
use bitcoin::Txid;
use serde::{ser::SerializeSeq, Deserialize, Serialize, Serializer};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum VersionKind {
    Single(String),
    MinMax(String, String),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum TxGetArgs {
    Txid((Txid,)),
    TxidVerbose(Txid, bool),
}

impl From<&TxGetArgs> for (Txid, bool) {
    fn from(args: &TxGetArgs) -> Self {
        match args {
            TxGetArgs::Txid((txid,)) => (*txid, false),
            TxGetArgs::TxidVerbose(txid, verbose) => (*txid, *verbose),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Params {
    #[serde(serialize_with = "default")]
    None,
    // NOTE: electrs does not support `cp_height` even if
    // it's in the 1.4 version spec. ...
    // https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-block-header
    // BlockHeader((usize /* height*/, usize /* cp_height */)),
    BlockHeader((usize /* height*/,)),
    // NOTE: idem
    BlockHeaders(
        (
            usize, /* start */
            usize, /* count */
                   // usize, /* cp_height */
        ),
    ),
    TransactionBroadcast((String,)),
    EstimateFee((u16,)),
    ScriptHashGetBalance((ScriptHash,)),
    ScriptHashGetHistory((ScriptHash,)),
    ScriptHashGetMempool((ScriptHash,)),
    ScriptHashListUnspent((ScriptHash,)),
    ScriptHashSubscribe((ScriptHash,)),
    ScriptHashUnsubscribe((ScriptHash,)),
    TransactionGet(TxGetArgs),
    TransactionGetMerkle((Txid, usize)),
    TransactionFromPosition(
        (
            usize, /*height*/
            usize, /*tx_pos*/
            bool,  /*merkle*/
        ),
    ),
    Version((String, VersionKind)),
}

fn default<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Serialize unit type as an empty array "[]"
    let sequence = serializer.serialize_seq(Some(0))?;
    sequence.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params() {
        assert_eq!(serde_json::to_string(&Params::None).unwrap(), "[]");
        assert_eq!(
            serde_json::to_string(&Params::BlockHeader((0,))).unwrap(),
            "[0]"
        );
    }
}
