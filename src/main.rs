// src/main.rs

//! # Decentralized Identity System - Main Entry Point
//!
//! This module serves as the main entry point for the Decentralized Identity (DID) system.
//! It initializes all core components and starts the API server.
//!
//! ## Architecture Overview
//! 1. **Blockchain Layer**: `ZkSyncClient` for interacting with zkSync Era L2
//! 2. **Services Layer**: Credential issuance, verification, and API endpoints
//! 3. **Storage Layer**: IPFS for decentralized document storage
//! 4. **Cryptography Layer**: Key management and zero-knowledge proofs
//!
//! ## Environment Variables Required
//! - `PRIVATE_KEY`: Ethereum wallet private key
//! - `CREDENTIAL_REGISTRY_ADDRESS`: Deployed CredentialRegistry contract address
//! - `DID_REGISTRY_ADDRESS`: Deployed DIDRegistry contract address  
//! - `PAYMASTER_ADDRESS`: Gas sponsorship contract address
//! - `IPFS_API_URL`: (Optional) IPFS node URL (default: http://localhost:5001)

use crate::blockchain::zksync_client::ZkSyncClient;
use crate::services::api_server::ApiServer;
use crate::services::credential_issuer::CredentialIssuer;
use crate::services::verifier::Verifier;
use crate::storage::ipfs_client::IpfsStorage;
use crate::wallet::key_management::KeyManager;
use std::sync::Arc;
use std::net::SocketAddr;
use dotenv::dotenv;

// Module declarations (organized by functional domain)
mod blockchain;    // zkSync blockchain interactions
mod services;      // Business logic and API
mod wallet;        // Cryptographic key operations  
mod storage;       // IPFS storage layer
mod zkp;           // Zero-knowledge proof utilities
mod models;        // Data structures
mod utils;         // Helper functions

/// Main application entry point
///
/// # Initialization Sequence
/// 1. Load environment configuration
/// 2. Connect to zkSync network
/// 3. Initialize service components
/// 4. Start API server
///
/// # Panics
/// - If required environment variables are missing
/// - If zkSync client fails to initialize
/// - If contract addresses are invalid
#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenv().ok();

    // Initialize the ZkSync client
    let private_key = std::env::var("PRIVATE_KEY")
        .expect("PRIVATE_KEY must be set in .env");
    let zksync_client = ZkSyncClient::new("https://sepolia.era.zksync.dev", &private_key)
        .await
        .expect("Failed to initialize ZkSyncClient - check network connection and private key");

    // Wrap client in Arc for thread-safe shared ownership across services
    let zksync_client_arc = Arc::new(zksync_client);

    // Load smart contract addresses
    let credential_registry_address = std::env::var("CREDENTIAL_REGISTRY_ADDRESS")
        .expect("CREDENTIAL_REGISTRY_ADDRESS must be set in .env");
    let did_registry_address = std::env::var("DID_REGISTRY_ADDRESS")
        .expect("DID_REGISTRY_ADDRESS must be set in .env");
    let paymaster_address = std::env::var("PAYMASTER_ADDRESS")
        .expect("PAYMASTER_ADDRESS must be set in .env");

    // Initialize core components
    let key_manager = KeyManager::new();  // Secp256k1 key management
    let ipfs_storage = IpfsStorage::new(); // IPFS client with default settings

    // Credential Issuer Service
    let credential_issuer = CredentialIssuer::new(
        zksync_client_arc.clone(),
        &credential_registry_address,
        &did_registry_address,
    )
    .expect("Failed to initialize CredentialIssuer - verify contract ABI and addresses");

    // Credential Verifier Service  
    let verifier = Verifier::new(zksync_client_arc.clone(), &credential_registry_address)
        .expect("Failed to initialize Verifier - check contract ABI");

    // Initialize API Server with all dependencies
    let api_server = ApiServer::new(
        credential_issuer,
        verifier,
        key_manager,
        ipfs_storage,
        zksync_client_arc,
        paymaster_address,
    );

    // Start the HTTP server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("API server running at http://{}", addr);
    println!("Available endpoints:");
    println!("- POST /create-did");
    println!("- GET  /resolve-did/:did"); 
    println!("- POST /issue-credential");
    println!("- POST /verify-proof");
    
    api_server.run(addr).await;
}