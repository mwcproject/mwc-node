# MWC Node Library Specification

This document specifies how to build and use `mwc_node_lib`, including its C interface and every JSON method handled in the library request dispatcher.

## Build

Run from repository root:

```bash
cargo build --package mwc_node_lib --lib
```

`mwc_node_lib` is built as `rlib`, `cdylib`, and `staticlib` (see `crate-type` in `mwc_node_lib/Cargo.toml`).

## C Interface

The C interface is is defined in:

- [mwc_node_lib/c_header/mwc_node_interface.h](https://github.com/mwcproject/mwc-node/blob/master/mwc_node_lib/c_header/mwc_node_interface.h)

Exported functions:

- `char *process_mwc_node_request(char const *input);` - Main API entry point. 'input' is a json string with API 
request call. Response is a C string that represent json format. Note, that string is managed in library side.
Use this string as a read only, don't store it in you code. When you copy, release it by calling 'free_node_lib_string'  

- `void free_node_lib_string(char *s);` - Release rust managed memory. 

- `void register_lib_callback(char const *callback_name, int8_t const *(*cb)(void *, int8_t const *), void *ctx);` - 
register callback function. 
  - 'callback_name' - name of this callback functions. This name will be used in other api calls.
  - 'ctx' - pointer to context that will be passed to your callback. 
  - 'cb' - callback declared as:
```
  extern "C"
     // ctx - yout internal context that you passed to register_lib_callback
     // msg - some message, usually it is a pointer to C strign in Json format. This memory is 
     // managed on rust side and is valid during this callback only. Don't store or modify it. 
    int8_t const * new_tx_callback(void* ctx, const int8_t* msg) {
         ...
    }
```

- `void unregister_lib_callback(char const *callback_name);` - unregister your callback by it's name.

Important callback lifetime rule:

- Callback message pointers are temporary and must not be stored on the C side. Copy data during callback execution.

## JSON Request/Response Contract

`process_mwc_node_request` receives a JSON string with this shape:

```json
{
  "method": "create_context",
  "params": {}
}
```

Success response:

```json
{
  "success": true,
  "result": {}
}
```

Error response:

```json
{
  "success": false,
  "error": "error details"
}
```

Pointer that 'process_mwc_node_request' returns, must be released with free_node_lib_string call.

## API Calls supported by process_mwc_node_request

All methods below are dispatched in:
[mwc_node_lib/src/mwc_node_calls.rs](https://github.com/mwcproject/mwc-node/blob/master/mwc_node_lib/src/mwc_node_calls.rs)

### 1) `create_context`

- Params:
  - `chain_type` (required): (`Floonet` or `Mainnet`)
  - `accept_fee_base` (optional): `u64`
  - `nrd_feature_enabled` (optional): `bool`
- Result:
  - `{ "context_id": <u32> }`
- Notes:
  - Allocates and initializes a context for chain/global settings.

### 2) `release_context`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Releases context resources and associated server data.

### 3) `init_file_logs`

- Params:
  - `config` (required): `LoggingConfig data in json format`
- Result:
  - `{}`
- Notes:
  - Initializes file/stdout logger using `LoggingConfig`. Use it if you don't want manage logs with your app
  and prefer store all node logs into a separate file.

### 4) `init_callback_logs`

- Params:
  - `log_callback_name` (required): `string` (callback that already registered with `register_lib_callback`)
  - `log_level` (required): `log::Level` (`Error`, `Warn`, `Info`, `Debug`, `Trace`)
  - `log_buffer_size` (optional): `usize` (default: `1000`)
- Result:
  - `{}`
- Notes:
  - Enables buffered logging and logs delivery through callback.
  - Callback receives one string line in the format `"<LEVEL> <message>"`.

### 5) `release_callback_logs`

- Params:
  - none
- Result:
  - `{}`
- Notes:
  - Disables callback logging.

### 6) `get_buffered_logs`

- Params:
  - `last_known_id` (optional): `u64`
  - `result_size_limit` (required): `usize`
- Result:
  - `{ "log_entries": [ ... ] }`
- Notes:
  - Returns buffered log entries (`id`, `time_stamp`, `log_entry`).

### 7) `start_tor`

- Params:
  - `config` (required): `TorConfig`
  - `base_dir` (required): `string`
- Result:
  - `{}`
- Notes:
  - Starts Arti Tor runtime. We recommend you start Tor core as soon as possible. 
  Node need Tor for p2p connecitons. 

### 8) `shutdown_tor`

- Params:
  - none
- Result:
  - `{}`
- Notes:
  - Stop Tor service and cancel all related tasks. Call it when you app is exiting, may be called before 'release_context'

### 9) `tor_status`

- Params:
  - none
- Result:
  - `{ "started": <bool>, "healthy": <bool> }`
- Notes: 
  - Use Tor 'healthy' result for monitoring and notifications. Node library will restore connection to the tor if possible.
  - Use tor 'started' result to track if start_tor task not failed. If might fail if it will not be able initiate connect to
  Tor network during few minutes.

### 10) `create_server`

- Params:
  - `context_id` (required): `u32`
  - `db_root` (required): `string` - path where the blockchin data will be stored.
  - `onion_expanded_key` (optional): `string` - Use onion expanded key to define specific Onion address. 
  This option make sense for seed nodes, so onion address will be constant. By default rando address will
  be generated on the first run.
  - `hook_callback_name` (optional): `string` (registered callback name) - Callback to receive events from the node. 
- Result:
  - `{}`
- Notes:
  - Creates server instance but does not start jobs.
  - Internally starts from `ServerConfig::default()` and sets:
    - `db_root`
    - `chain_type` from context
    - `p2p_config.onion_expanded_key`
  - If `hook_callback_name` is provided, callback receives JSON:
    - `{ "context_id": <u32>, "event": "<event_name>", "data": <json> }`
  - Event names emitted by server hooks include:
    - `header_received`
    - `block_received`
    - `transaction_received`
    - `block_accepted`

### 11) `release_server`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Stop the node. Note, it doesn't release all resources. 'release_context' call is expected as well.

### 12) `init_call_api`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starting foreign API. Note, that API will not listen on the web, requests are expected to come through 'process_api_call'  

### 13) `process_api_call`

- Params:
  - `context_id` (required): `u32`
  - `method` (required): `string` (HTTP method) : API call method. Use "POST" for foreign API calls
  - `uri` (required): `string` (request URI) : use "/v2/foreign" for foreign API calls
  - `body` (required): `string` (raw request body)
- Result:
  - `{ "response": "<response_body_as_string>" }`
- Notes:
  - 'body' and 'response' details check of mwc-node foreign API documentation. 
  - mwc-node using rust json convention that is different from JS or C++ Qt. Long values must be converted and keep all bits, not 7 bytes. 

### 14) `start_stratum`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starts stratum mining service.

### 15) `start_discover_peers`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starts peer discovery job.

### 16) `start_sync_monitoring`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starts node sync monitoring job.

### 17) `start_listen_peers`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starts inbound peer listener in background mode.

### 18) `start_dandelion`

- Params:
  - `context_id` (required): `u32`
- Result:
  - `{}`
- Notes:
  - Starts Dandelion service.

### 19) `get_server_stats`

- Params:
  - `context_id` (required): `u32`
- Result:
  - Serialized `ServerStats` object
- Notes:
  - Includes peer count, chain/header stats, sync status, stratum stats, peer stats, tx stats, disk usage.


# Example of the usage

This library is used for MWC-QT-Wallet. Please use it as an example of integration with a C++ applicaiton.

- [mwc-qt-wallet/node/MwcNodeApi.h](https://github.com/mwcproject/mwc-qt-wallet/blob/master/node/MwcNodeApi.h)
- [mwc-qt-wallet/node/MwcNodeApi.cpp](https://github.com/mwcproject/mwc-qt-wallet/blob/master/node/MwcNodeApi.cpp)
