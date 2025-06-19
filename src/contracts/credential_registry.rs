// src/contracts/credential_registry.rs
//! Credential Registry smart contract interface.
//!
//! Provides a high-level API for interacting with the Verifiable Credential registry
//! on zkSync network. Supports issuing, revoking, and verifying credentials on-chain.

use crate::models::credential::VerifiableCredential;
use zksync_web3_rs::types::{Address, H256};
use zksync_web3_rs::providers::{Provider, JsonRpcClient};
use zksync_web3_rs::contract::Contract;
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::str::FromStr;

/// Credential Registry smart contract wrapper.
///
/// This struct provides methods to interact with the Credential Registry contract:
/// - Issue new verifiable credentials
/// - Revoke existing credentials
/// - Verify credential status
///
/// # Type Parameters
/// * `P` - JSON-RPC client implementation (e.g., `Http`)
pub struct CredentialRegistry<P> {
    /// Underlying contract instance
    contract: Contract<Provider<P>>,
}

impl<P> CredentialRegistry<P>
where
    P: JsonRpcClient + 'static,
{
    /// Creates a new CredentialRegistry instance.
    ///
    /// # Arguments
    /// * `provider` - zkSync provider instance
    /// * `contract_address` - Address of deployed CredentialRegistry contract
    ///
    /// # Panics
    /// Panics if the contract ABI cannot be loaded
    pub fn new(provider: Provider<P>, contract_address: Address) -> Self {
        let contract = Contract::from_json(
            provider,
            contract_address,
            include_bytes!("../abi/CredentialRegistry.json"),
        )
        .expect("Failed to load contract ABI");
        CredentialRegistry { contract }
    }

    /// Issues a new verifiable credential on-chain.
    ///
    /// # Arguments
    /// * `credential` - VerifiableCredential to issue
    ///
    /// # Returns
    /// Transaction hash of the issuance operation
    ///
    /// # Gas Usage
    /// Uses approximately 3,000,000 gas units
    pub async fn issue_credential(
        &self,
        credential: VerifiableCredential,
    ) -> Result<H256, Box<dyn Error>> {
        let credential_json = serde_json::to_string(&credential)?;

        let method = self.contract
            .method::<_, H256>("issueCredential", (credential_json,))?
            .gas(3000000_u64);

        let pending_tx = method.send().await?;
        Ok(pending_tx.tx_hash())
    }

    /// Revokes an existing verifiable credential.
    ///
    /// # Arguments
    /// * `credential_id` - Unique identifier of the credential to revoke
    ///
    /// # Returns
    /// Transaction hash of the revocation operation
    ///
    /// # Gas Usage
    /// Uses approximately 3,000,000 gas units
    pub async fn revoke_credential(
        &self,
        credential_id: String,
    ) -> Result<H256, Box<dyn Error>> {
        let method = self.contract
            .method::<_, H256>("revokeCredential", (credential_id,))?
            .gas(3000000_u64);

        let pending_tx = method.send().await?;
        Ok(pending_tx.tx_hash())
    }

    /// Verifies a credential's on-chain status.
    ///
    /// # Arguments
    /// * `credential_id` - Unique identifier of the credential to verify
    ///
    /// # Returns
    /// - `true` if credential exists and is not revoked
    /// - `false` if credential is revoked or doesn't exist
    pub async fn verify_credential(
        &self,
        credential_id: String,
    ) -> Result<bool, Box<dyn Error>> {
        let method = self.contract
            .method::<_, bool>("verifyCredential", (credential_id,))?;

        let is_valid = method.call().await?;
        Ok(is_valid)
    }
}

/// Example usage of the Credential Registry.
///
/// Demonstrates:
/// 1. Connecting to zkSync
/// 2. Initializing the registry
/// 3. Issuing a credential
/// 4. Verifying a credential
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to zkSync testnet
    let provider = Provider::<Http>::try_from("https://sepolia.era.zksync.dev")?;

    // Initialize with actual contract address
    let contract_address = Address::from_str(std::env::var("CREDENTIAL_REGISTRY_ADDRESS"))?;
    let credential_registry = CredentialRegistry::new(provider, contract_address);

    // Issue example credential
    let credential = VerifiableCredential {
        id: "vc:example:123".to_string(),
        issuer: "did:example:issuer".to_string(),
        subject: "did:example:subject".to_string(),
        claims: vec![("degree".to_string(), "Bachelor".to_string())],
        signature: vec![1, 2, 3], // In production, use real cryptographic signature
    };

    let tx_hash = credential_registry.issue_credential(credential).await?;
    println!("Credential issued with tx hash: {:?}", tx_hash);

    // Verify credential status
    let is_valid = credential_registry.verify_credential("vc:example:123".to_string()).await?;
    println!("Credential validity: {}", is_valid);

    Ok(())
}