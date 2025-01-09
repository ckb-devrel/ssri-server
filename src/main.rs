use ckb_jsonrpc_types::{OutPoint, Script, TransactionView};
use ckb_types::H256;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::tracing;
use jsonrpsee::types::ErrorObjectOwned;

mod error;
mod rpc_client;
mod ssri_vm;
mod types;

use error::Error;
use hyper::Method;
use rpc_client::RpcClient;
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};
use types::{CellOutputWithData, Hex, VmResult};

use ssri_vm::execute_riscv_binary;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    ckb_rpc: String,
    server_addr: String,
    script_debug: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ckb_rpc: "https://testnet.ckb.dev/".to_string(),
            server_addr: "0.0.0.0:9090".to_string(),
            script_debug: true,
        }
    }
}

#[rpc(server)]
pub trait Rpc {
    #[method(name = "run_script_level_code")]
    async fn run_script_level_code(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
    ) -> Result<VmResult, ErrorObjectOwned>;

    #[method(name = "run_script_level_script")]
    async fn run_script_level_script(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
        script: Script,
    ) -> Result<VmResult, ErrorObjectOwned>;

    #[method(name = "run_script_level_cell")]
    async fn run_script_level_cell(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
        cell: CellOutputWithData,
    ) -> Result<VmResult, ErrorObjectOwned>;

    #[method(name = "run_script_level_tx")]
    async fn run_script_level_tx(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
        tx: TransactionView,
    ) -> Result<VmResult, ErrorObjectOwned>;
}

pub struct RpcServerImpl {
    config: Config,
    rpc: RpcClient,
}

impl RpcServerImpl {
    pub fn new(config: Config) -> Self {
        Self {
            rpc: RpcClient::new(&config.ckb_rpc),
            config,
        }
    }

    async fn run_script(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
        script: Option<Script>,
        cell: Option<CellOutputWithData>,
        tx: Option<TransactionView>,
    ) -> Result<VmResult, ErrorObjectOwned> {
        let ssri_cell = self
            .rpc
            .get_live_cell(
                &OutPoint {
                    tx_hash: tx_hash.0.into(),
                    index: index.into(),
                },
                true,
            )
            .await?;

        let ssri_binary = ssri_cell
            .cell
            .ok_or(Error::InvalidRequest("Cell not found"))?
            .data
            .ok_or(Error::InvalidRequest("Cell doesn't have data"))?
            .content
            .into_bytes();

        let script = script.map(Into::into);
        let cell = cell.map(Into::into);
        let tx = tx.map(|v| v.inner.into());
        let description = format!(
            "Script {tx_hash}:{index} with args {args:?} context\nscript: {script:?}\ncell: {cell:?}\ntx: {tx:?}"
        );

        let args = args.into_iter().map(|v| v.hex.into()).collect();
        let res = execute_riscv_binary(
            self.config.clone(),
            self.rpc.clone(),
            ssri_binary,
            args,
            script,
            cell,
            tx,
        )?;
        tracing::info!("{description}\nresult {res:?}");

        Ok(res)
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn run_script_level_code(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
    ) -> Result<VmResult, ErrorObjectOwned> {
        self.run_script(tx_hash, index, args, None, None, None)
            .await
    }

    async fn run_script_level_script(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
        script: Script,
    ) -> Result<VmResult, ErrorObjectOwned> {
        self.run_script(tx_hash, index, args, Some(script), None, None)
            .await
    }

    async fn run_script_level_cell(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
        cell: CellOutputWithData,
    ) -> Result<VmResult, ErrorObjectOwned> {
        self.run_script(tx_hash, index, args, None, Some(cell), None)
            .await
    }

    async fn run_script_level_tx(
        &self,
        tx_hash: H256,
        index: u32,
        args: Vec<Hex>,
        tx: TransactionView,
    ) -> Result<VmResult, ErrorObjectOwned> {
        self.run_script(tx_hash, index, args, None, None, Some(tx))
            .await
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .expect("setting default subscriber failed");

    // Start with default config
    let mut config = Config::default();

    // Try to load from config file
    if let Ok(file_config) = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()
    {
        if let Ok(deserialized_config) = file_config.try_deserialize::<Config>() {
            config = deserialized_config;
        }
    }

    println!(
        "CKB RPC URI: {}\nListening on: {}\nScript debug {}",
        config.ckb_rpc,
        config.server_addr,
        if config.script_debug {
            "enabled"
        } else {
            "disabled"
        }
    );
    run_server(config).await?;
    Ok(())
}

async fn run_server(config: Config) -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        // Allow `POST` when accessing the resource
        .allow_methods([Method::POST])
        // Allow requests from any origin
        .allow_origin(Any)
        .allow_headers([hyper::header::CONTENT_TYPE]);
    let middleware = tower::ServiceBuilder::new().layer(cors);
    let server = Server::builder()
        .set_http_middleware(middleware)
        .build(&config.server_addr)
        .await?;

    let handle = server.start(RpcServerImpl::new(config).into_rpc());

    tokio::signal::ctrl_c().await.unwrap();
    handle.stop().unwrap();

    Ok(())
}
