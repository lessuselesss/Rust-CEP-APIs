use circular_enterprise_apis::CepAccount;
use dotenv::dotenv;
use std::env;
use log::{info, error, LevelFilter};
use env_logger::Builder;

#[tokio::main]
async fn main() {
    // Initialize logger
    Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    // Load environment variables from .env file
    dotenv().ok();

    // Retrieve environment variables
    let private_key = env::var("CIRCULAR_PRIVATE_KEY")
        .expect("CIRCULAR_PRIVATE_KEY not set in .env file");
    let address = env::var("CIRCULAR_ADDRESS")
        .expect("CIRCULAR_ADDRESS not set in .env file");

    // Initialize CepAccount
    let mut account = CepAccount::new();
    if !account.open(&address) {
        error!("Failed to open account: {:?}", account.get_last_error());
        return;
    }

    // Set network (e.g., "testnet")
    let nag_url = account.set_network("testnet").await;
    if nag_url.is_empty() {
        error!("Failed to set network: {:?}", account.get_last_error());
        return;
    }
    info!("Connected to NAG: {}", nag_url);

    // Update account nonce
    if !account.update_account().await {
        error!("Failed to update account: {:?}", account.get_last_error());
        return;
    }
    info!("Account nonce updated. Current Nonce: {}", account.nonce);

    // Create and submit a certificate
    let certificate_data = "Hello, Circular Protocol from Rust!";
    account.submit_certificate(certificate_data, &private_key).await;
    if let Some(err) = account.get_last_error() {
        error!("Failed to submit certificate: {}", err);
        return;
    }
    info!("Certificate submitted. Latest Transaction ID: {}", account.latest_tx_id);

    // Poll for transaction outcome
    info!("Polling for transaction outcome...");
    let latest_tx_id = account.latest_tx_id.clone();
    let outcome = account.get_transaction_outcome(&latest_tx_id, 60, 5).await; // 60s timeout, 5s interval
    if outcome.is_none() {
        error!("Failed to get transaction outcome: {:?}", account.get_last_error());
        return;
    }
    info!("Transaction Outcome: {:?}", outcome.unwrap());

    // Close the account test
    account.close();
    info!("Account closed.");
}
