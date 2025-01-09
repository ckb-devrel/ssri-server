use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ckb_jsonrpc_types::{CellOutput, Either, JsonBytes, TransactionWithStatusResponse, Uint32};
use ckb_sdk::rpc::ckb_indexer::{Cell, Order, Pagination, SearchKey};
use ckb_types::H256;
use jsonrpc_core::serde_json;
use reqwest::blocking::Client;
use reqwest::Url;

use crate::error::Error;

macro_rules! jsonrpc {
    ($method:expr, $self:ident, $return:ty$(, $params:ident$(,)?)*) => {{
        let data = format!(
            r#"{{"id": {}, "jsonrpc": "2.0", "method": "{}", "params": {}}}"#,
            $self.id.load(Ordering::Relaxed),
            $method,
            serde_json::to_value(($($params,)*)).unwrap()
        );
        $self.id.fetch_add(1, Ordering::Relaxed);

        let req_json: serde_json::Value = serde_json::from_str(&data).unwrap();

        let c = $self.raw.post($self.uri.clone()).json(&req_json);
        let resp = c
            .send()
            .map_err::<Error, _>(|_| Error::JsonRpcRequestError)?;
        let output = resp
            .json::<jsonrpc_core::response::Output>()
            .map_err::<Error, _>(|_| Error::JsonRpcRequestError)?;

        match output {
            jsonrpc_core::response::Output::Success(success) => {
                Ok(serde_json::from_value::<$return>(success.result).unwrap())
            }
            jsonrpc_core::response::Output::Failure(_) => {
                Err(Error::JsonRpcRequestError)
            }
        }
    }}
}

#[derive(Clone)]
pub struct RpcClient {
    raw: Client,
    uri: Url,
    id: Arc<AtomicU64>,
}

impl RpcClient {
    pub fn new(ckb_uri: &str) -> Self {
        let uri = Url::parse(ckb_uri).expect("ckb uri, e.g. \"http://127.0.0.1:8114\"");

        RpcClient {
            raw: Client::new(),
            uri,
            id: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl RpcClient {
    pub fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: u32,
        cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>, Error> {
        let limit = Uint32::from(limit);
        jsonrpc!(
            "get_cells",
            self,
            Pagination<Cell>,
            search_key,
            order,
            limit,
            cursor,
        )
    }

    pub fn get_cell(
        &self,
        tx_hash: &H256,
        index: u32,
    ) -> Result<Option<(CellOutput, JsonBytes)>, Error> {
        let tx = self.get_transaction(tx_hash)?;
        let tx = match tx {
            Some(TransactionWithStatusResponse {
                transaction: Some(tx),
                ..
            }) => tx.inner,
            _ => return Ok(None),
        };

        let tx = match tx {
            Either::Left(view) => view,
            Either::Right(bytes) => match serde_json::from_slice(&bytes.into_bytes()) {
                Err(_) => return Ok(None),
                Ok(view) => view,
            },
        }
        .inner;

        let output = tx.outputs.get(index as usize);
        let data = tx.outputs_data.get(index as usize);
        match (output, data) {
            (Some(output), Some(data)) => Ok(Some((output.clone(), data.clone()))),
            _ => Ok(None),
        }
    }

    pub fn get_transaction(
        &self,
        hash: &H256,
    ) -> Result<Option<TransactionWithStatusResponse>, Error> {
        jsonrpc!(
            "get_transaction",
            self,
            Option<TransactionWithStatusResponse>,
            hash,
        )
    }
}
