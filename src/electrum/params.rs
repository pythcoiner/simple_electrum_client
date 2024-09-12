use super::types::ScriptHash;
use bitcoin::Txid;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize, Serializer};

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

// impl Params {
//     fn parse(method: &str, params: Value) -> std::result::Result<Params, Error> {
//         Ok(match method {
//             "blockchain.block.header" => Params::BlockHeader(convert(params)?),
//             "blockchain.block.headers" => Params::BlockHeaders(convert(params)?),
//             "blockchain.estimatefee" => Params::EstimateFee(convert(params)?),
//             "blockchain.scripthash.get_balance" => Params::ScriptHashGetBalance(convert(params)?),
//             "blockchain.scripthash.get_history" => Params::ScriptHashGetHistory(convert(params)?),
//             "blockchain.scripthash.listunspent" => Params::ScriptHashListUnspent(convert(params)?),
//             "blockchain.scripthash.subscribe" => Params::ScriptHashSubscribe(convert(params)?),
//             "blockchain.scripthash.unsubscribe" => Params::ScriptHashUnsubscribe(convert(params)?),
//             "blockchain.transaction.broadcast" => Params::TransactionBroadcast(convert(params)?),
//             "blockchain.transaction.get" => Params::TransactionGet(convert(params)?),
//             "blockchain.transaction.get_merkle" => Params::TransactionGetMerkle(convert(params)?),
//             "blockchain.transaction.id_from_pos" => {
//                 Params::TransactionFromPosition(convert(params)?)
//             }
//             "server.version" => Params::Version(convert(params)?),
//             _ => {
//                 log::warn!("unknown method {}", method);
//                 return Err(Error::MethodNotFound);
//             }
//         })
//     }
// }
//
// fn convert<T>(params: Value) -> std::result::Result<T, Error>
// where
//     T: serde::de::DeserializeOwned,
// {
//     let params_str = params.to_string();
//     serde_json::from_value(params).map_err(|err| {
//         log::warn!("invalid params {}: {}", params_str, err);
//         Error::InvalidParam
//     })
// }

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
