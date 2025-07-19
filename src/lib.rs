use chrono::Utc;
use hex;
use lazy_static::lazy_static;
use parking_lot::Mutex;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use secp256k1::{Message, SecretKey, Secp256k1};
use tokio;

/// Common constants and functions used across the Circular Enterprise APIs library.
///
/// This module defines fundamental constants and shared utilities that are integral
/// to the operation of the API, including versioning, default blockchain identifiers,
/// and network discovery URLs.

/// The current version of the Circular Enterprise APIs Rust library.
///
/// This constant is used to track the library's version and can be included in
/// API requests to indicate the client's version.
pub const LIB_VERSION: &str = "1.0.13";

/// The default blockchain identifier used for transactions and account operations.
///
/// This hexadecimal string represents a specific blockchain network that the API
/// interacts with by default.
pub const DEFAULT_CHAIN: &str = "0x8a20baa40c45dc5055aeb26197c203e576ef389d9acb171bd62da11dc5ad72b2";

/// The default Network Access Gateway (NAG) URL.
///
/// This URL serves as the base for discovering network-specific endpoints.
pub const DEFAULT_NAG: &str = "https://nag.circularlabs.io/NAG.php?cep=";

lazy_static! {
    /// A lazily initialized static mutex containing the base URL for network discovery.
    ///
    /// This URL is used to fetch the appropriate Network Access Gateway (NAG) for a
    /// given network. It is wrapped in a `Mutex` to allow for safe, mutable access
    /// across multiple threads, particularly useful for testing or dynamic configuration.
    pub static ref NETWORK_URL: Mutex<String> = Mutex::new("https://circularlabs.io/network/getNAG?network=".to_string());
}

/// Represents the structure of a response received from the Network Access Gateway (NAG) service.
///
/// This struct is used to deserialize the JSON response when querying for a NAG URL,
/// providing information about the status of the request, the URL itself, and any
/// associated messages.
#[derive(Deserialize)]
struct NagResponse {
    /// The status of the NAG request (e.g., "success", "error").
    status: String,
    /// The URL returned by the NAG service, if the request was successful.
    url: String,
    /// A message providing additional details about the NAG response.
    message: String,
}

/// Fetches the Network Access Gateway (NAG) URL for a given network identifier.
///
/// This asynchronous function queries the network discovery service to retrieve
/// the appropriate NAG URL. It performs validation on the input and the received
/// response to ensure a valid URL is returned.
///
/// # Arguments
///
/// * `network` - A string slice representing the network identifier (e.g., "testnet", "mainnet").
///
/// # Returns
///
/// A `Result` which is:
/// - `Ok(String)` containing the NAG URL if the request is successful and the response is valid.
/// - `Err(String)` containing an error message if the network identifier is empty,
///   the network request fails, the response status is not OK, or the NAG response
///   indicates an error or contains an invalid URL.
pub async fn get_nag(network: &str) -> Result<String, String> {
    if network.is_empty() {
        return Err("network identifier cannot be empty".to_string());
    }

    let request_url = format!("{}{}", NETWORK_URL.lock(), network);
    let response = reqwest::get(&request_url).await.map_err(|e| format!("failed to fetch NAG URL: {}", e))?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("network discovery failed with status: {}", response.status()));
    }

    let nag_response = response.json::<NagResponse>().await.map_err(|e| format!("failed to unmarshal NAG response: {}", e))?;

    if nag_response.status == "error" {
        return Err(format!("failed to get valid NAG URL from response: {}", nag_response.message));
    }

    if nag_response.status != "success" || nag_response.url == "" {
        return Err(format!("failed to get valid NAG URL from response: {}", nag_response.message));
    }

    Ok(nag_response.url)
}

#[cfg(test)]
mod common_tests {
    use super::*;
    use httpmock::prelude::*;
    use lazy_static::lazy_static;
    use parking_lot::Mutex;

    // Use a Mutex to safely modify NETWORK_URL for testing
    lazy_static! {
        static ref TEST_NETWORK_URL_MUTEX: Mutex<String> = Mutex::new(NETWORK_URL.lock().clone());
    }

    #[tokio::test]
    async fn test_get_nag() {
        let mock_server = MockServer::start();

        // Store the original NETWORK_URL
        let original_network_url = NETWORK_URL.lock().clone();

        // Temporarily change NETWORK_URL to point to the mock server
        *NETWORK_URL.lock() = format!("http://127.0.0.1:{}/network/getNAG?network=", mock_server.port());

        // Test case 1: Successful response
        let success_mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/network/getNAG")
                .query_param("network", "testnet");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"status":"success", "url":"https://nag.circularlabs.io/NAG.php?cep=", "message":"OK"}"#);
        });

        let result = get_nag("testnet").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://nag.circularlabs.io/NAG.php?cep=");
        success_mock.assert();

        // Test case 2: Error response from server
        let error_mock = mock_server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/network/getNAG")
                .query_param("network", "devnet");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"status":"error", "url":"", "message":"Network not found"}"#);
        });

        let result = get_nag("devnet").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "failed to get valid NAG URL from response: Network not found");
        error_mock.assert();

        // Test case 3: Empty network identifier
        let result = get_nag("").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "network identifier cannot be empty");

        // Restore original NETWORK_URL
        *NETWORK_URL.lock() = original_network_url;
    }
}

/// Represents a Circular Enterprise API (CEP) certificate.
///
/// This struct encapsulates the data, previous transaction ID, previous block,
/// and version information for a certificate within the Circular Protocol.
/// It is designed to be serialized to JSON for submission to the network.
#[derive(Serialize)]
pub struct CCertificate {
    /// The main data content of the certificate, typically hex-encoded.
    pub data: String,
    /// The ID of the previous transaction in the blockchain, if applicable.
    #[serde(rename = "previousTxID")]
    pub previous_tx_id: String,
    /// The identifier of the previous block in the blockchain, if applicable.
    #[serde(rename = "previousBlock")]
    pub previous_block: String,
    /// The version of the certificate format or the library used to create it.
    pub version: String,
}

impl CCertificate {
    /// Creates a new `CCertificate` instance with default empty values.
    ///
    /// The `version` field is initialized with the `LIB_VERSION` constant.
    ///
    /// # Returns
    ///
    /// A new `CCertificate` instance.
    pub fn new() -> Self {
        Self {
            data: "".to_string(),
            previous_tx_id: "".to_string(),
            previous_block: "".to_string(),
            version: LIB_VERSION.to_string(),
        }
    }

    /// Sets the data content of the certificate.
    ///
    /// The provided string data is converted to its hexadecimal representation
    /// before being stored.
    ///
    /// # Arguments
    ///
    /// * `data` - A string slice containing the data to be set.
    pub fn set_data(&mut self, data: &str) {
        self.data = string_to_hex(data);
    }

    /// Retrieves the data content of the certificate.
    ///
    /// The stored hexadecimal data is converted back to its original string
    /// representation.
    ///
    /// # Returns
    ///
    /// A `String` containing the decoded data.
    pub fn get_data(&self) -> String {
        hex_to_string(&self.data)
    }

    /// Returns the JSON string representation of the certificate.
    ///
    /// This method serializes the `CCertificate` struct into a JSON string.
    ///
    /// # Returns
    ///
    /// A `String` containing the JSON representation of the certificate.
    /// Returns an empty string if serialization fails.
    pub fn get_json_certificate(&self) -> String {
        match serde_json::to_string(&self) {
            Ok(json_string) => json_string,
            Err(_) => "".to_string(),
        }
    }

    /// Calculates the size of the JSON string representation of the certificate.
    ///
    /// # Returns
    ///
    /// A `usize` representing the length of the JSON string.
    pub fn get_certificate_size(&self) -> usize {
        self.get_json_certificate().len()
    }

    /// Sets the previous transaction ID for the certificate.
    ///
    /// # Arguments
    ///
    /// * `tx_id` - A string slice containing the previous transaction ID.
    pub fn set_previous_tx_id(&mut self, tx_id: &str) {
        self.previous_tx_id = tx_id.to_string();
    }

    /// Sets the previous block identifier for the certificate.
    ///
    /// # Arguments
    ///
    /// * `block` - A string slice containing the previous block identifier.
    pub fn set_previous_block(&mut self, block: &str) {
        self.previous_block = block.to_string();
    }

    /// Retrieves the previous transaction ID of the certificate.
    ///
    /// # Returns
    ///
    /// A `String` containing the previous transaction ID.
    pub fn get_previous_tx_id(&self) -> String {
        self.previous_tx_id.clone()
    }

    /// Retrieves the previous block identifier of the certificate.
    ///
    /// # Returns
    ///
    /// A `String` containing the previous block identifier.
    pub fn get_previous_block(&self) -> String {
        self.previous_block.clone()
    }
}

/// Represents a Circular Enterprise Protocol (CEP) account.
///
/// This struct holds all the necessary information and state for interacting
/// with the Circular network on behalf of a specific account, including its
/// address, public key, network configuration, and transaction-related data.
pub struct CepAccount {
    /// The hexadecimal address of the account.
    pub address: String,
    /// The public key associated with the account, in hexadecimal format.
    pub public_key: String,
    /// Optional additional information about the account, typically in JSON format.
    pub info: Option<Value>,
    /// The version of the client code interacting with the network.
    pub code_version: String,
    /// Stores the last encountered error message, if any, during account operations.
    pub last_error: Option<String>,
    /// The URL of the Network Access Gateway (NAG) currently in use.
    pub nag_url: String,
    /// The identifier of the network node being used (e.g., "testnet").
    pub network_node: String,
    /// The blockchain identifier the account is operating on.
    pub blockchain: String,
    /// The ID of the most recently submitted transaction from this account.
    pub latest_tx_id: String,
    /// A nonce value used for transaction ordering and replay protection.
    pub nonce: i64,
    /// The interval in seconds for polling operations, such as transaction outcomes.
    pub interval_sec: i32,
    /// The base URL for network discovery.
    pub network_url: String,
}

impl CepAccount {
    /// Creates a new `CepAccount` instance with default initial values.
    ///
    /// Most fields are initialized to empty strings or `None`, while `code_version`,
    /// `nag_url`, `blockchain`, `nonce`, `interval_sec`, and `network_url` are
    /// set to their respective default or initial values.
    ///
    /// # Returns
    ///
    /// A new `CepAccount` instance.
    pub fn new() -> Self {
        Self {
            address: "".to_string(),
            public_key: "".to_string(),
            info: None,
            code_version: LIB_VERSION.to_string(),
            last_error: None,
            nag_url: DEFAULT_NAG.to_string(),
            network_node: "".to_string(),
            blockchain: DEFAULT_CHAIN.to_string(),
            latest_tx_id: "".to_string(),
            nonce: 0,
            interval_sec: 2,
            network_url: NETWORK_URL.lock().to_string(),
        }
    }

    /// Retrieves the last error message encountered by the account.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the error message if an error occurred,
    /// or `None` if there was no recent error.
    pub fn get_last_error(&self) -> Option<String> {
        self.last_error.clone()
    }

    /// Opens the account by setting its address.
    ///
    /// This method validates the provided address and updates the account's
    /// internal state. If the address is empty, an error is set.
    ///
    /// # Arguments
    ///
    /// * `address` - A string slice representing the hexadecimal address of the account.
    ///
    /// # Returns
    ///
    /// `true` if the account was successfully opened, `false` otherwise.
    pub fn open(&mut self, address: &str) -> bool {
        if address.is_empty() {
            self.last_error = Some("invalid address format".to_string());
            return false;
        }
        self.address = address.to_string();
        true
    }

    /// Closes the account by clearing its sensitive and network-related information.
    ///
    /// This resets the account to a default, uninitialized state, effectively
    /// logging out or disconnecting the account.
    pub fn close(&mut self) {
        self.address = "".to_string();
        self.public_key = "".to_string();
        self.info = None;
        self.nag_url = "".to_string();
        self.network_node = "".to_string();
        self.blockchain = "".to_string();
        self.latest_tx_id = "".to_string();
        self.nonce = 0;
        self.interval_sec = 0;
    }

    /// Sets the network for the account by fetching the appropriate NAG URL.
    ///
    /// This asynchronous method uses the provided network identifier to query
    /// the network discovery service and update the account's `nag_url` and
    /// `network_node` fields. If the NAG URL cannot be retrieved, an error
    /// is set.
    ///
    /// # Arguments
    ///
    /// * `network` - A string slice representing the network identifier (e.g., "testnet").
    ///
    /// # Returns
    ///
    /// A `String` containing the fetched NAG URL if successful, or an empty string
    /// if an error occurred during the network discovery process.
    pub async fn set_network(&mut self, network: &str) -> String {
        match get_nag(network).await {
            Ok(url) => {
                self.nag_url = url.clone();
                self.network_node = network.to_string();
                url
            }
            Err(e) => {
                self.last_error = Some(e);
                "".to_string()
            }
        }
    }

    /// Sets the blockchain identifier for the account.
    ///
    /// # Arguments
    ///
    /// * `chain` - A string slice representing the blockchain identifier.
    pub fn set_blockchain(&mut self, chain: &str) {
        self.blockchain = chain.to_string();
    }

    /// Updates the account's nonce by querying the network.
    ///
    /// This asynchronous method sends a request to the network to retrieve
    /// the latest nonce for the account's address. It handles various network
    /// responses and updates the `nonce` field accordingly. If the account
    /// is not open or a network error occurs, `last_error` is set.
    ///
    /// # Returns
    ///
    /// `true` if the account update was successful and the nonce was retrieved,
    /// `false` otherwise.
    pub async fn update_account(&mut self) -> bool {
        if self.address.is_empty() {
            self.last_error = Some("Account not open".to_string());
            return false;
        }

        let request_data = serde_json::json!({
            "Address": hex_fix(&self.address),
            "Version": self.code_version,
            "Blockchain": hex_fix(&self.blockchain),
        });

        let url = format!("{}Circular_GetWalletNonce_{}", self.nag_url, self.network_node);
        let client = reqwest::Client::new();
        let res = client.post(&url).json(&request_data).send().await;

        match res {
            Ok(response) => {
                if response.status() != reqwest::StatusCode::OK {
                    self.last_error = Some(format!("network request failed with status: {}", response.status()));
                    return false;
                }

                match response.json::<serde_json::Value>().await {
                    Ok(data) => {
                        if let Some(result) = data.get("Result").and_then(|r| r.as_i64()) {
                            if result == 200 {
                                if let Some(nonce) = data.get("Response").and_then(|r| r.get("Nonce")).and_then(|n| n.as_i64()) {
                                    self.nonce = nonce + 1;
                                    return true;
                                } else {
                                    self.last_error = Some("failed to decode nonce response".to_string());
                                    return false;
                                }
                            } else if result == 114 {
                                self.last_error = Some("Rejected: Invalid Blockchain".to_string());
                                return false;
                            } else if result == 115 {
                                self.last_error = Some("Rejected: Insufficient balance".to_string());
                                return false;
                            } else {
                                if let Some(err_msg) = data.get("Response").and_then(|r| r.as_str()) {
                                    self.last_error = Some(format!("failed to update account: {}", err_msg));
                                } else {
                                    self.last_error = Some("failed to update account: unknown error response".to_string());
                                }
                                return false;
                            }
                        } else {
                            self.last_error = Some("failed to get result from response".to_string());
                            return false;
                        }
                    }
                    Err(e) => {
                        self.last_error = Some(format!("failed to decode response body: {}", e));
                        false
                    }
                }
            }
            Err(e) => {
                self.last_error = Some(format!("http request failed: {}", e));
                false
            }
        }
    }

    /// Signs a message using the account's private key.
    ///
    /// This method takes a message and a hexadecimal private key, then uses
    /// `secp256k1` to sign the message. The resulting signature is returned
    /// in hexadecimal format. Debugging information is optionally written to
    /// `rust_sign_debug.log`.
    ///
    /// # Arguments
    ///
    /// * `message` - A string slice representing the message to be signed.
    /// * `private_key_hex` - A string slice containing the private key in hexadecimal format.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok(String)` containing the hexadecimal signature if successful.
    /// - `Err(String)` containing an error message if the account is not open,
    ///   the private key is invalid, or the signing process fails.
    fn sign_data(&self, message: &str, private_key_hex: &str) -> Result<String, String> {
        if self.address.is_empty() {
            return Err("account is not open".to_string());
        }

        let private_key_bytes = match hex::decode(hex_fix(private_key_hex)) {
            Ok(bytes) => bytes,
            Err(e) => return Err(format!("invalid private key hex string: {}", e)),
        };

        // Ensure the private key is exactly 32 bytes
        let private_key_array: [u8; 32] = private_key_bytes.try_into().map_err(|_| "private key must be 32 bytes long".to_string())?;

        let secp = Secp256k1::new();
        let private_key = match SecretKey::from_byte_array(private_key_array) {
            Ok(key) => key,
            Err(e) => return Err(format!("invalid private key: {}", e)),
        };

        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        let message = Message::from_digest(hash.into());
        let sig = secp.sign_ecdsa(message, &private_key);

        let sig_hex = hex::encode(sig.serialize_der().as_ref());

        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open("rust_sign_debug.log") {
            writeln!(file, "Rust SignData Debug:").unwrap();
            writeln!(file, "  Message: {}", message).unwrap();
            writeln!(file, "  Private Key (hex): {}", private_key_hex).unwrap();
            writeln!(file, "  Message Hash (hex): {}", hex::encode(hash)).unwrap();
            writeln!(file, "  Signature (hex): {}", sig_hex).unwrap();
            writeln!(file, "").unwrap();
        }

        Ok(sig_hex)
    }

    /// Submits a certificate to the Circular network.
    ///
    /// This asynchronous method constructs a transaction payload, signs it
    /// using the provided private key, and sends it to the network via the
    /// configured NAG URL. It handles various network responses and updates
    /// the account's `latest_tx_id` and `nonce` upon successful submission.
    /// Errors encountered during the process are stored in `last_error`.
    ///
    /// # Arguments
    ///
    /// * `pdata` - A string slice containing the payload data for the certificate.
    /// * `private_key_hex` - A string slice containing the private key in hexadecimal format.
    pub async fn submit_certificate(&mut self, pdata: &str, private_key_hex: &str) {
        if self.address.is_empty() {
            self.last_error = Some("Account is not open".to_string());
            return;
        }

        let payload_object = serde_json::json!({
            "Action": "CP_CERTIFICATE",
            "Data": string_to_hex(pdata),
        });
        let payload = string_to_hex(&payload_object.to_string());
        let timestamp = get_formatted_timestamp();

        let str_to_hash = format!("{}{}{}{}{}{}", hex_fix(&self.blockchain), hex_fix(&self.address), hex_fix(&self.address), payload, self.nonce, timestamp);
        let mut hasher = Sha256::new();
        hasher.update(str_to_hash.as_bytes());
        let hash = hasher.finalize();
        let id = hex::encode(hash);

        let signature = match self.sign_data(&id, private_key_hex) {
            Ok(sig) => sig,
            Err(e) => {
                self.last_error = Some(format!("failed to sign data: {}", e));
                return;
            }
        };

        let request_data = serde_json::json!({
            "ID": id,
            "From": hex_fix(&self.address),
            "To": hex_fix(&self.address),
            "Timestamp": timestamp,
            "Payload": payload,
            "Nonce": self.nonce.to_string(),
            "Signature": signature,
            "Blockchain": hex_fix(&self.blockchain),
            "Type": "C_TYPE_CERTIFICATE",
            "Version": self.code_version,
        });

        let url = format!("{}Circular_AddTransaction_{}", self.nag_url, self.network_node);
        let client = reqwest::Client::new();
        let res = client.post(&url).json(&request_data).send().await;

        match res {
            Ok(response) => {
                if response.status() != reqwest::StatusCode::OK {
                    self.last_error = Some(format!("network request failed with status: {}", response.status()));
                    return;
                }

                match response.json::<serde_json::Value>().await {
                    Ok(data) => {
                        if let Some(result) = data.get("Result").and_then(|r| r.as_i64()) {
                            if result == 200 {
                                self.latest_tx_id = id;
                                self.nonce += 1;
                            } else {
                                if let Some(err_msg) = data.get("Response").and_then(|r| r.as_str()) {
                                    self.last_error = Some(format!("certificate submission failed: {}", err_msg));
                                } else {
                                    self.last_error = Some("certificate submission failed with non-200 result code".to_string());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        self.last_error = Some(format!("failed to decode response JSON: {}", e));
                    }
                }
            }
            Err(e) => {
                self.last_error = Some(format!("failed to submit certificate: {}", e));
            }
        }
    }

    /// Retrieves a transaction from the network by its block ID and transaction ID.
    ///
    /// This asynchronous method queries the network for a specific transaction.
    /// It validates the `block_id` and handles potential parsing errors.
    /// The actual fetching is delegated to `get_transaction_by_id`.
    /// Errors encountered are stored in `last_error`.
    ///
    /// # Arguments
    ///
    /// * `block_id` - A string slice representing the block ID where the transaction is located.
    /// * `transaction_id` - A string slice representing the ID of the transaction to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option<Value>` containing the transaction data as a JSON `Value` if successful,
    /// or `None` if an error occurred or the transaction was not found.
    pub async fn get_transaction(&mut self, block_id: &str, transaction_id: &str) -> Option<Value> {
        if block_id.is_empty() {
            self.last_error = Some("blockID cannot be empty".to_string());
            return None;
        }

        let start_block = match block_id.parse::<i64>() {
            Ok(id) => id,
            Err(e) => {
                self.last_error = Some(format!("invalid blockID: {}", e));
                return None;
            }
        };

        match self.get_transaction_by_id(transaction_id, start_block, start_block).await {
            Ok(result) => Some(result),
            Err(e) => {
                self.last_error = Some(format!("failed to get transaction by ID: {}", e));
                None
            }
        }
    }

    /// Internal asynchronous method to retrieve a transaction by its ID within a block range.
    ///
    /// This method constructs and sends a request to the network to fetch transaction
    /// details. It handles network responses and JSON parsing. This is a private
    /// helper function used by `get_transaction` and `get_transaction_outcome`.
    ///
    /// # Arguments
    ///
    /// * `transaction_id` - A string slice representing the ID of the transaction.
    /// * `start_block` - The starting block number for the search range.
    /// * `end_block` - The ending block number for the search range.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok(Value)` containing the transaction data as a JSON `Value` if successful.
    /// - `Err(String)` containing an error message if the network is not set,
    ///   the network request fails, or JSON decoding fails.
    async fn get_transaction_by_id(&self, transaction_id: &str, start_block: i64, end_block: i64) -> Result<Value, String> {
        if self.nag_url.is_empty() {
            return Err("network is not set".to_string());
        }

        let request_data = serde_json::json!({
            "Blockchain": hex_fix(&self.blockchain),
            "ID": hex_fix(transaction_id),
            "Start": start_block.to_string(),
            "End": end_block.to_string(),
            "Version": self.code_version,
        });

        let url = format!("{}Circular_GetTransactionbyID_{}", self.nag_url, self.network_node);
        let client = reqwest::Client::new();
        let res = client.post(&url).json(&request_data).send().await;

        match res {
            Ok(response) => {
                if response.status() != reqwest::StatusCode::OK {
                    return Err(format!("network request failed with status: {}", response.status()));
                }

                match response.json::<Value>().await {
                    Ok(data) => Ok(data),
                    Err(e) => Err(format!("failed to decode transaction JSON: {}", e)),
                }
            }
            Err(e) => Err(format!("http post failed: {}", e)),
        }
    }

    /// Polls the network to get the outcome of a transaction within a specified timeout.
    ///
    /// This asynchronous method repeatedly queries the network for the status of a
    /// transaction until it is no longer "Pending" or a timeout is reached. It uses
    /// `get_transaction_by_id` internally for polling. Errors encountered during
    /// polling or if a timeout occurs are stored in `last_error`.
    ///
    /// # Arguments
    ///
    /// * `tx_id` - A string slice representing the ID of the transaction to poll.
    /// * `timeout_sec` - The maximum time in seconds to wait for the transaction outcome.
    /// * `interval_sec` - The interval in seconds between polling attempts.
    ///
    /// # Returns
    ///
    /// An `Option<Value>` containing the transaction outcome data as a JSON `Value`
    /// if the transaction is executed, or `None` if a timeout occurs or an error
    /// prevents retrieval.
    pub async fn get_transaction_outcome(&mut self, tx_id: &str, timeout_sec: i32, interval_sec: i32) -> Option<Value> {
        if self.nag_url.is_empty() {
            self.last_error = Some("network is not set".to_string());
            return None;
        }

        let timeout = tokio::time::Duration::from_secs(timeout_sec as u64);
        let interval = tokio::time::Duration::from_secs(interval_sec as u64);

        let start_time = tokio::time::Instant::now();

        loop {
            if start_time.elapsed() > timeout {
                self.last_error = Some("timeout exceeded while waiting for transaction outcome".to_string());
                return None;
            }

            match self.get_transaction_by_id(tx_id, 0, 10).await {
                Ok(data) => {
                    if let Some(result) = data.get("Result").and_then(|r| r.as_i64()) {
                        if result == 200 {
                            if let Some(response) = data.get("Response") {
                                if let Some(status) = response.get("Status").and_then(|s| s.as_str()) {
                                    if status != "Pending" {
                                        return Some(response.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Polling error: {}. Retrying.", e);
                }
            }

            tokio::time::sleep(interval).await;
        }
    }
}


/// Pads a number with a leading zero if it is a single digit.
///
/// This utility function is typically used for formatting numbers (e.g., hours, minutes)
/// to ensure a consistent two-digit representation.
///
/// # Arguments
///
/// * `num` - An `i32` integer to be padded.
///
/// # Returns
///
/// A `String` representation of the number, padded with a leading zero if `0 <= num < 10`.
pub fn pad_number(num: i32) -> String {
    if num >= 0 && num < 10 {
        format!("0{}", num)
    } else {
        num.to_string()
    }
}

/// Generates a formatted timestamp string in "YYYY:MM:DD-HH:MM:SS" format.
///
/// This utility function uses the current UTC time to create a consistent
/// timestamp string, suitable for use in transaction data or logging.
///
/// # Returns
///
/// A `String` containing the formatted timestamp.
pub fn get_formatted_timestamp() -> String {
    Utc::now().format("%Y:%m:%d-%H:%M:%S").to_string()
}

/// Cleans and normalizes a hexadecimal string.
///
/// This utility function performs the following operations:
/// 1. Removes "0x" or "0X" prefixes.
/// 2. Converts the string to lowercase.
/// 3. Pads the string with a leading '0' if its length is odd.
///
/// # Arguments
///
/// * `hex_str` - A string slice representing the hexadecimal string to fix.
///
/// # Returns
///
/// A `String` containing the cleaned and normalized hexadecimal string.
pub fn hex_fix(hex_str: &str) -> String {
    if hex_str.is_empty() {
        return "".to_string();
    }

    let mut s = hex_str.to_string();

    // Remove "0x" or "0X" prefix
    if s.starts_with("0x") || s.starts_with("0X") {
        s = s[2..].to_string();
    }

    // Convert to lower
    s = s.to_lowercase();

    // Pad with '0' if length is odd
    if s.len() % 2 != 0 {
        s = "0".to_string() + &s;
    }

    s
}

/// Converts a string to its hexadecimal representation.
///
/// Each byte of the input string is converted into its two-digit uppercase
/// hexadecimal equivalent.
///
/// # Arguments
///
/// * `s` - A string slice to be converted to hexadecimal.
///
/// # Returns
///
/// A `String` containing the uppercase hexadecimal representation of the input string.
pub fn string_to_hex(s: &str) -> String {
    hex::encode(s.as_bytes()).to_uppercase()
}

/// Converts a hexadecimal string back to its original string representation.
///
/// This utility function decodes a hexadecimal string into bytes and then
/// attempts to convert those bytes into a UTF-8 string. It handles optional
/// "0x" or "0X" prefixes.
///
/// # Arguments
///
/// * `hex_str` - A string slice representing the hexadecimal string to decode.
///
/// # Returns
///
/// A `String` containing the decoded string. Returns an empty string if the
/// input is empty or if decoding/conversion fails.
pub fn hex_to_string(hex_str: &str) -> String {
    if hex_str.is_empty() {
        return "".to_string();
    }

    let mut s = hex_str.to_string();

    // Remove "0x" or "0X" prefix if present
    if s.starts_with("0x") || s.starts_with("0X") {
        s = s[2..].to_string();
    }

    // Decode the hex string to bytes
    match hex::decode(&s) {
        Ok(decoded_bytes) => String::from_utf8_lossy(&decoded_bytes).to_string(),
        Err(_) => "".to_string(), // Return empty string on error, matching Java's behavior
    }
}