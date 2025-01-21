# SSRI Executor JSON RPC Server

> SSRI-server has been renamed to `ssri-executor-jsonrpc`.

## Quick Start

### Docker (Recommended)

```shell
docker run -p 9090:9090 hanssen0/ckb-ssri-server
```

### Local Development

Start server with

```sh
RUST_LOG=ssri_server=debug cargo run
```

### Configuration

Use `config.toml` and `config.mainnet.toml` to configure the server.

```toml
ckb_rpc = "https://testnet.ckb.dev/"
server_addr = "0.0.0.0:9090"

script_debug = false
```

## Interacting with the Executor

### (Recommended if Available) Use full-fledged dedicated SDK like [`@ckb-ccc/udt`](https://docs.ckbccc.com/modules/_ckb_ccc_udt.html)

- These SDKs are:
  - built with full-fledged SSRI support,
  - comprehensive documentations,
  - additional features that were well-designed with elevated functionality.
- See detailed guidance to currently available SDKs:
  - [`@ckb-ccc/udt`](https://docs.ckbccc.com/modules/_ckb_ccc_udt.html)

### (Alternative) Use [`@ckb-ccc/ssri`](https://docs.ckbccc.com/modules/_ckb_ccc_ssri.html) to for light implementation or build your own SDK

- You can quickly implement your own SDK or just use it in an ad-hoc manner by extending `ssri.Trait`
- [`@ckb-ccc/udt`](https://docs.ckbccc.com/modules/_ckb_ccc_udt.html) which is built on top of `ssri.Trait` is a good example to follow.

### (For debugging purpose or resource-constrained environment) Calling the Executor directly

Run a script with

```sh
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "run_script_level_code",
    "params": ["0xb442eda5c133387c345d1e081d36b5163e09fd665d20b8ae0abe5a2366b851ee", 0, ["0x58f02409de9de7b1", "0x0000000000000000", "0x0a00000000000000"]]
}' \
| curl -H 'content-type: application/json' -d @- \
http://localhost:9090
```

Or using executable script like `bash ./test.sh`.

## Obtaining the Correct Params

Currently, obtaining the correct params for calling SSRI methods depends on `ckb_std::high_level::decode_hex`.

For example, you get the param to call "SSRI.get_methods" by running the following code in the script:

```rust
  let get_methods_path = method_path("SSRI.get_methods");
  let get_methods_path_in_bytes = get_methods_path.to_le_bytes();
  let get_methods_path_path_hex = encode_hex(&get_methods_path_in_bytes);
  // get_methods_path_hex is `0x58f02409de9de7b1`
```

For best experience, use the SDKs mentioned above as they have incorporated the details of serialization and deserialization. If inevitable, use [Molecule-Parser](https://explorer.nervos.org/tools/molecule-parser) to parse the molecule data.

## Attempt for WASM

> https://github.com/rustwasm/wasm-bindgen/issues/2753

- Due to the limitations of WASM and browser related runtime that are single-threaded, as CKB-VM currently requires `Sync` and `Send` for trait `Syscall`, it is not promising to implement running CKB-VM in the browser with WASM.
- However, new efforts are being made to implement CKB-VM in the browser with WASM as [ckb-light-client](https://github.com/nervosnetwork/ckb-light-client) has been making progress.
