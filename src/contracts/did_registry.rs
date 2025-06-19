// src/contracts/did_registry.rs
//! DID Registry smart contract interface implementation.
//!
//! Provides an abstraction layer for interacting with the DID Registry smart contract
//! on zkSync network. Supports create, resolve, and update operations for DIDs.

use crate::models::did::DIDDocument;
use zksync_web3_rs::types::{Address, H256};
use zksync_web3_rs::providers::{Provider, JsonRpcClient};
use zksync_web3_rs::contract::Contract;
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::str::FromStr;
use dotenv::dotenv;

/// DID Registry smart contract interface.
///
/// This struct provides high-level methods to interact with the DID Registry contract:
/// - DID creation
/// - DID resolution
/// - DID updates
///
/// # Type Parameters
/// * `P` - JSON-RPC client implementation
///
pub struct DIDRegistry<P> {
    /// Underlying contract instance
    contract: Contract<Provider<P>>,
}

impl<P> DIDRegistry<P>
where
    P: JsonRpcClient + 'static,
{
    /// Creates a new DIDRegistry instance.
    ///
    /// # Arguments
    /// * `provider` - zkSync provider instance
    /// * `contract_address` - Address of deployed DIDRegistry contract
    ///
    /// # Panics
    /// Panics if the contract ABI cannot be loaded
    pub fn new(provider: Provider<P>, contract_address: Address) -> Self {
        let contract = Contract::from_json(
            provider,
            contract_address,
            include_bytes!("../abi/DIDRegistry.json"),
        )
        .expect("Failed to load contract ABI");
        DIDRegistry { contract }
    }

    /// Creates a new DID on-chain.
    ///
    /// # Arguments
    /// * `did` - DID string identifier
    /// * `document` - Initial DID Document
    ///
    /// # Returns
    /// Transaction hash of the create operation
    ///
    /// # Gas Usage
    /// Uses approximately 3,000,000 gas units
    pub async fn create_did(
        &self,
        did: String,
        document: DIDDocument,
    ) -> Result<H256, Box<dyn Error>> {
        let document_json = serde_json::to_string(&document)?;

        let method = self.contract
            .method::<_, H256>("createDID", (did, document_json))?
            .gas(3000000_u64);

        let pending_tx = method.send().await?;
        Ok(pending_tx.tx_hash())
    }

    /// Resolves a DID to its current DID Document.
    ///
    /// # Arguments
    /// * `did` - DID string identifier to resolve
    ///
    /// # Returns
    /// Current DID Document associated with the DID
    pub async fn resolve_did(
        &self,
        did: String,
    ) -> Result<DIDDocument, Box<dyn Error>> {
        let method = self.contract
            .method::<_, String>("resolveDID", (did,))?;

        let document_json = method.call().await?;
        let document: DIDDocument = serde_json::from_str(&document_json)?;
        Ok(document)
    }

    /// Updates an existing DID's document.
    ///
    /// # Arguments
    /// * `did` - DID string identifier to update
    /// * `document` - New DID Document
    ///
    /// # Returns
    /// Transaction hash of the update operation
    ///
    /// # Gas Usage
    /// Uses approximately 3,000,000 gas units
    pub async fn update_did(
        &self,
        did: String,
        document: DIDDocument,
    ) -> Result<H256, Box<dyn Error>> {
        let document_json = serde_json::to_string(&document)?;

        let method = self.contract
            .method::<_, H256>("updateDID", (did, document_json))?
            .gas(3000000_u64);

        let pending_tx = method.send().await?;
        Ok(pending_tx.tx_hash())
    }
}

/// Example main function demonstrating DID Registry usage.
///
/// Shows complete workflow:
/// 1. Connecting to zkSync
/// 2. Initializing registry
/// 3. Creating a DID
/// 4. Resolving a DID
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to zkSync testnet
    let provider = Provider::<Http>::try_from("https://sepolia.era.zksync.dev")?;

    // Initialize with actual contract address
    let contract_address = Address::from_str(std::env::var("DID_REGISTRY_ADDRESS"))?;
    let did_registry = DIDRegistry::new(provider, contract_address);

    // Create example DID
    let did = "did:example:123".to_string();
    let document = DIDDocument {
        id: did.clone(),
        public_key: vec![1, 2, 3], // Example key bytes
        service_endpoint: "https://example.com".to_string(),
    };

    let tx_hash = did_registry.create_did(did.clone(), document).await?;
    println!("DID created with transaction hash: {:?}", tx_hash);

    // Resolve the created DID
    let resolved_document = did_registry.resolve_did(did).await?;
    println!("Resolved DID document: {:?}", resolved_document);

    Ok(())
}