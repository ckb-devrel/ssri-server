# SSRI Server

Start server with

```sh
RUST_LOG=ssri_server=debug cargo run
```

Run a script with

```sh
echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "run_script_level_code",
    "params": ["0x900afcf79235e88f7bdf8a5d320365b7912f8074f4489a68405f43586fc51e5c", 0, ["0x58f02409de9de7b1", "0x0000000000000000", "0x0a00000000000000"]]
}' \
| curl -H 'content-type: application/json' -d @- \
http://localhost:8090
```

## Obtaining the Correct Params

Currently, obtaining the correct params for calling SSRI methods depends on `ckb_std::high_level::decode_hex`.

For example, you get the param to call "SSRI.get_methods" by running the following code in the script:

```rust
  let get_methods_path = method_path("SSRI.get_methods");
  let get_methods_path_in_bytes = get_methods_path.to_le_bytes();
  let get_methods_path_path_hex = encode_hex(&get_methods_path_in_bytes);
  // get_methods_path_hex is `0x58f02409de9de7b1`
```