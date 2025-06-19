// src/services/verifier.rs
//! Credential verification service for the DID system.
//!
//! This module provides functionality to verify credentials against the on-chain
//! CredentialRegistry contract using zkSync blockchain interactions.

use crate::blockchain::zksync_client::ZkSyncClient;
use zksync_web3_rs::types::Address;
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

/// Credential verifier that interacts with the blockchain CredentialRegistry.
///
/// The Verifier provides:
/// - Thread-safe credential verification via Arc<ZkSyncClient>
/// - Address formatting utilities
/// - Async verification operations
pub struct Verifier {
    /// Thread-safe zkSync client for blockchain operations
    zksync_client: Arc<ZkSyncClient>,
    /// Ethereum address of the deployed CredentialRegistry contract
    credential_registry_address: Address,
}

impl Verifier {
    /// Constructs a new Verifier instance.
    ///
    /// # Arguments
    /// * `zksync_client` - Thread-safe reference to initialized zkSync client
    /// * `credential_registry_address` - Hex string of contract address (with or without 0x prefix)
    ///
    /// # Errors
    /// Returns `Err` if:
    /// - Address string is malformed
    /// - Address has incorrect length
    pub fn new(
        zksync_client: Arc<ZkSyncClient>,
        credential_registry_address: &str,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            zksync_client,
            credential_registry_address: Address::from_str(credential_registry_address)?,
        })
    }

    /// Formats an Ethereum address as a lowercase hex string with 0x prefix.
    ///
    /// # Arguments
    /// * `addr` - The Ethereum address to format
    ///
    /// # Returns
    /// String representation of the address (e.g., "0x1234abcd...")
    ///
    /// # Note
    /// This is an internal helper method and doesn't validate the address.
    fn format_address(addr: Address) -> String {
        format!("0x{:x}", addr)
    }

    /// Verifies a credential's validity by querying the CredentialRegistry contract.
    ///
    /// # Arguments
    /// * `credential_id` - The unique identifier of the credential to verify
    ///
    /// # Returns
    /// - `Ok(true)` if credential is valid
    /// - `Ok(false)` if credential is invalid
    /// - `Err` if:
    ///   - Blockchain query fails
    ///   - Contract call reverts
    ///   - ABI decoding fails
    ///
    /// # Process Flow
    /// 1. Formats contract address
    /// 2. Loads contract ABI (compile-time included)
    /// 3. Calls `verifyCredential` view function
    /// 4. Returns boolean result
    pub async fn verify_credential(&self, credential_id: String) -> Result<bool, Box<dyn Error>> {
        self.zksync_client
            .query_contract(
                &Self::format_address(self.credential_registry_address),
                include_bytes!("abi/CredentialRegistry.json"),
                "verifyCredential",
                credential_id,
            )
            .await
    }
}

