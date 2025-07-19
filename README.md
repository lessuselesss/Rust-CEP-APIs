# Circular Enterprise APIs - Rust Implementation

Official Circular Protocol Enterprise APIs for Data Certification - Rust Implementation

## Features

- Account management and blockchain interaction (`CepAccount`)
- Certificate creation and submission (`CCertificate`)
- Transaction tracking and verification
- Secure digital signatures using ECDSA (secp256k1)
- Asynchronous network operations with `tokio`

## Requirements

- Rust (latest stable version recommended)

## Dependencies

This project relies on the following Rust crates:

- `chrono`: Date and time utilities.
- `hex`: Hexadecimal encoding and decoding.
- `lazy_static`: For lazily initialized static variables.
- `parking_lot`: Efficient synchronization primitives.
- `reqwest`: Asynchronous HTTP client.
- `secp256k1`: For ECDSA cryptographic operations.
- `serde`: Serialization and deserialization framework.
- `serde_json`: JSON serialization and deserialization.
- `sha2`: SHA-2 hashing algorithm.
- `tokio`: Asynchronous runtime.
- `dotenv`: For loading environment variables from a `.env` file.
- `log`: Logging facade.
- `env_logger`: A logging implementation for `log`.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/circular-protocol/Rust-Enterprise-APIs.git
    ```
2.  Navigate to the project directory:
    ```bash
    cd Rust-Enterprise-APIs
    ```
3.  Build the project (this will also download dependencies):
    ```bash
    cargo build
    ```

## Usage Example

See `examples/simple_certificate_submission.rs` for a basic example of how to use the API to submit a certificate.

## API Documentation

### `CepAccount` Struct

Main struct for interacting with the Circular blockchain:

-   `new()`: Factory function to create a new `CepAccount` instance.
-   `open(address: &str)`: Initializes the account with a specified blockchain address.
-   `close()`: Clears all sensitive and operational data from the account.
-   `set_network(network: &str)`: Configures the account to operate on a specific blockchain network by fetching the appropriate NAG URL.
-   `set_blockchain(chain: &str)`: Explicitly sets the blockchain identifier for the account.
-   `update_account()`: Fetches the latest nonce for the account from the NAG.
-   `submit_certificate(pdata: &str, private_key_hex: &str)`: Creates, signs, and submits a data certificate to the blockchain.
-   `get_transaction(block_id: &str, transaction_id: &str)`: Retrieves transaction details by block and transaction ID.
-   `get_transaction_outcome(tx_id: &str, timeout_sec: i32, interval_sec: i32)`: Polls for the final status of a transaction.
-   `get_last_error()`: Retrieves the last error message.

### `CCertificate` Struct

Struct for managing certificates:

-   `new()`: Factory function to create a new `CCertificate` instance.
-   `set_data(data: &str)`: Sets the primary data content of the certificate (converts to hex).
-   `get_data()`: Retrieves the primary data content from the certificate (decodes from hex).
-   `get_json_certificate()`: Serializes the certificate object into a JSON string.
-   `get_certificate_size()`: Calculates the size of the JSON-serialized certificate in bytes.
-   `set_previous_tx_id(tx_id: &str)`: Sets the transaction ID of the preceding certificate.
-   `set_previous_block(block: &str)`: Sets the block identifier of the preceding certificate.
-   `get_previous_tx_id()`: Retrieves the transaction ID of the preceding certificate.
-   `get_previous_block()`: Retrieves the block identifier of the preceding certificate.

## Testing

To run the tests, you need to set up the following environment variables in a `.env` file in the project root:

```
CIRCULAR_PRIVATE_KEY="your_64_character_private_key_here"
CIRCULAR_ADDRESS="your_account_address_here"
```

The private key should be a 64-character (32-byte) hex string acquired from circular connect, and the address should be a valid Ethereum-style address (40 characters + 0x prefix).

### Running Tests

```bash
cargo test
```

## Building

```bash
cargo build --release
```

This will build the optimized release version of the library.

## License

MIT License - see LICENSE file for details

## Credits

CIRCULAR GLOBAL LEDGERS, INC. - USA

- Original Version: Gianluca De Novi, PhD
- Rust Implementation: [Ashley Barr]
