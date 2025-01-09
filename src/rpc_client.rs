use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ckb_jsonrpc_types::{CellWithStatus, JsonBytes, OutPoint, Uint32};
use ckb_sdk::rpc::ckb_indexer::{Cell, Order, Pagination, SearchKey};
use ckb_sdk::CkbRpcClient;
use jsonrpc_core::futures::FutureExt;
use jsonrpc_core::serde_json;
use reqwest::{Client, Url};

use crate::error::Error;

pub type RpcResponse<T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'static>>;

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
        async {
            let resp = c
                .send()
                .await
                .map_err::<Error, _>(|_| Error::JsonRpcRequestError)?;
            let output = resp
                .json::<jsonrpc_core::response::Output>()
                .await
                .map_err::<Error, _>(|_| Error::JsonRpcRequestError)?;

            match output {
                jsonrpc_core::response::Output::Success(success) => {
                    Ok(serde_json::from_value::<$return>(success.result).unwrap())
                }
                jsonrpc_core::response::Output::Failure(_) => {
                    Err(Error::JsonRpcRequestError)
                }
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
    pub fn get_live_cell(
        &self,
        out_point: &OutPoint,
        with_data: bool,
    ) -> RpcResponse<CellWithStatus> {
        jsonrpc!("get_live_cell", self, CellWithStatus, out_point, with_data).boxed()
    }

    pub fn get_cells(
        &self,
        search_key: SearchKey,
        limit: u32,
        cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>, ckb_sdk::RpcError> {
        let order = Order::Asc;
        let limit = Uint32::from(limit);

        // jsonrpc!(
        //     "get_cells",
        //     self,
        //     Pagination<Cell>,
        //     search_key,
        //     order,
        //     limit,
        //     cursor,
        // )
        // .boxed()
        let ckb_client = CkbRpcClient::new("https://testnet.ckbapp.dev/");
        ckb_client.get_cells(search_key, order, limit, cursor)
    }

    pub fn get_live_cell_ckb(
        &self,
        out_point: &OutPoint,
        with_data: bool,
    ) -> Result<CellWithStatus, ckb_sdk::rpc::RpcError> {
        let ckb_client = CkbRpcClient::new("https://testnet.ckbapp.dev/");
        ckb_client.get_live_cell(out_point.to_owned(), with_data)
    }
}
