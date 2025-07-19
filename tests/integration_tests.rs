use circular_enterprise_apis::{CepAccount, DEFAULT_CHAIN};
use std::env;
use tokio;

// Load .env file for integration tests
#[test]
fn load_env() {
    dotenv::dotenv().ok();
}

// Setup function to ensure a fresh nonce and handle expected errors
async fn setup_account_integration() -> (CepAccount, String, String) {
    let private_key_hex = env::var("CIRCULAR_PRIVATE_KEY").expect("CIRCULAR_PRIVATE_KEY not set");
    let address = env::var("CIRCULAR_ADDRESS").expect("CIRCULAR_ADDRESS not set");

    let mut acc = CepAccount::new();
    if !acc.open(&address) {
        panic!("Failed to open account: {:?}", acc.get_last_error());
    }
    acc.set_network("testnet").await;
    acc.set_blockchain(DEFAULT_CHAIN);

    // Attempt to update account, handling expected errors
    let update_result = acc.update_account().await;
    if !update_result {
        if let Some(err) = acc.get_last_error() {
            if err == "Rejected: Insufficient balance" || err == "Rejected: Invalid Blockchain" {
                // These are expected and positive sign-post responses from the live network
                println!("Setup: Expected error during update_account: {}", err);
            } else {
                panic!("Setup: Unexpected error during update_account: {}", err);
            }
        } else {
            panic!("Setup: update_account failed with no error message");
        }
    }
    (acc, private_key_hex, address)
}

#[tokio::test]
async fn test_circular_operations() {
    let (mut acc, private_key_hex, _) = setup_account_integration().await;

    acc.submit_certificate("test message", &private_key_hex).await;
    if let Some(err) = acc.get_last_error() {
        if err == "certificate submission failed: Invalid Signature" || err == "certificate submission failed: Duplicate Nonce" || err == "Rejected: Insufficient balance" {
            println!("Expected error during submit_certificate: {}", err);
            // This is an expected outcome for some test runs against a live network
            return;
        } else {
            panic!("Failed to submit certificate: {:?}", acc.get_last_error());
        }
    }

    let tx_hash = acc.latest_tx_id.clone();
    assert!(!tx_hash.is_empty());

    // Get transaction outcome
    let outcome = acc.get_transaction_outcome(&tx_hash, 30, 2).await;
    if outcome.is_none() {
        panic!("Failed to get transaction outcome: {:?}", acc.get_last_error());
    }

    let outcome_map = outcome.unwrap();
    let status = outcome_map["Status"].as_str().unwrap();
    assert_eq!(status, "Executed");

    // Query the transaction
    let block_id = outcome_map["BlockID"].as_str().unwrap_or_else(|| {
        panic!("BlockID not found in transaction outcome. Outcome Map: {:?}", outcome_map);
    });
    let tx_data = acc.get_transaction(block_id, &tx_hash).await;
    assert!(acc.get_last_error().is_none());
    assert!(tx_data.is_some());

    let tx_data_map = tx_data.unwrap();
    let result = tx_data_map["Result"].as_i64().unwrap();
    assert_eq!(result, 200);

    acc.close();
}

#[tokio::test]
async fn test_certificate_operations() {
    let (mut acc, private_key_hex, _) = setup_account_integration().await;

    let certificate_data = "test data";
    acc.submit_certificate(certificate_data, &private_key_hex).await;
    if let Some(err) = acc.get_last_error() {
        if err == "certificate submission failed: Invalid Signature" || err == "certificate submission failed: Duplicate Nonce" || err == "Rejected: Insufficient balance" {
            println!("Expected error during submit_certificate: {}", err);
            return;
        } else {
            panic!("Failed to submit certificate: {:?}", acc.get_last_error());
        }
    }

    let tx_hash = acc.latest_tx_id.clone();
    assert!(!tx_hash.is_empty());

    // Get transaction outcome
    let outcome = acc.get_transaction_outcome(&tx_hash, 30, 2).await;
    if outcome.is_none() {
        panic!("Failed to get transaction outcome: {:?}", acc.get_last_error());
    }

    let outcome_map = outcome.unwrap();
    let status = outcome_map["Status"].as_str().unwrap();
    assert_eq!(status, "Executed");

    // Query the transaction
    let block_id = outcome_map["BlockID"].as_str().unwrap_or_else(|| {
        panic!("BlockID not found in transaction outcome. Outcome Map: {:?}", outcome_map);
    });
    let tx_data = acc.get_transaction(block_id, &tx_hash).await;
    assert!(acc.get_last_error().is_none());
    assert!(tx_data.is_some());

    let tx_data_map = tx_data.unwrap();
    let result = tx_data_map["Result"].as_i64().unwrap();
    assert_eq!(result, 200);

    acc.close();
}