    echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "run_script_level_code",
    "params": ["0xb442eda5c133387c345d1e081d36b5163e09fd665d20b8ae0abe5a2366b851ee", 0, ["0x58f02409de9de7b1", "0x0000000000000000", "0x0a00000000000000"]]
}' \
| curl -H 'content-type: application/json' -d @- \
http://localhost:9090