// src/services/credential_issuer.rs
//! Credential Issuer Service
//!
//! This module provides functionality for managing Decentralized Identifiers (DIDs)
//! and issuing/revoking verifiable credentials on the zkSync blockchain.
//!
//! The service interacts with two smart contracts:
//! - DID Registry: For creating, resolving, and updating DIDs
//! - Credential Registry: For issuing and revoking verifiable credentials

use crate::blockchain::zksync_client::ZkSyncClient;
use crate::models::credential::VerifiableCredential;
use crate::models::did::DIDDocument;
use zksync_web3_rs::types::{Address, H256};
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

/// Service for managing DIDs and verifiable credentials on blockchain
///
/// Handles all interactions with the DID Registry and Credential Registry
/// smart contracts to provide a clean interface for:
/// - DID lifecycle management (create/resolve/update)
/// - Credential operations (issue/revoke)
pub struct CredentialIssuer {
    /// Client for interacting with zkSync blockchain
    zksync_client: Arc<ZkSyncClient>,
    
    /// Address of the Credential Registry smart contract
    credential_registry_address: Address,
    
    /// Address of the DID Registry smart contract
    did_registry_address: Address,
}

impl CredentialIssuer {
    /// Creates a new CredentialIssuer instance
    ///
    /// # Arguments
    /// * `zksync_client` - Configured client for zkSync blockchain interactions
    /// * `credential_registry_address` - Hex string of Credential Registry contract address
    /// * `did_registry_address` - Hex string of DID Registry contract address
    ///
    /// # Returns
    /// Result containing initialized CredentialIssuer or error if address parsing fails
    pub fn new(
        zksync_client: Arc<ZkSyncClient>,
        credential_registry_address: &str,
        did_registry_address: &str,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            zksync_client,
            credential_registry_address: Address::from_str(credential_registry_address)?,
            did_registry_address: Address::from_str(did_registry_address)?,
        })
    }

    /// Helper function to format an Address as a hex string with 0x prefix
    fn format_address(addr: Address) -> String {
        format!("0x{:x}", addr)
    }

    /// Creates a new Decentralized Identifier (DID) on blockchain
    ///
    /// # Arguments
    /// * `document` - DID document containing identifier, public key, and service endpoint
    ///
    /// # Returns
    /// Result containing transaction hash if successful, or error
    pub async fn create_did(&self, document: DIDDocument) -> Result<H256, Box<dyn Error>> {
        let document_json = serde_json::to_string(&document)?;
        self.zksync_client
            .send_transaction(
                &Self::format_address(self.did_registry_address),
                include_bytes!("abi/DIDRegistry.json"),
                "createDID",
                (document.id, document_json),
            )
            .await
    }

    /// Resolves a DID to its document representation from blockchain
    ///
    /// # Arguments
    /// * `did` - The DID string to resolve
    ///
    /// # Returns
    /// Result containing parsed DID document or error
    pub async fn resolve_did(&self, did: String) -> Result<DIDDocument, Box<dyn Error>> {
        let document_json: String = self.zksync_client
            .query_contract(
                &Self::format_address(self.did_registry_address),
                include_bytes!("abi/DIDRegistry.json"),
                "resolveDID",
                did,
            )
            .await?;

        serde_json::from_str(&document_json).map_err(Into::into)
    }

    /// Updates an existing DID document on blockchain
    ///
    /// # Arguments
    /// * `did` - The DID string to update
    /// * `document` - New DID document contents
    ///
    /// # Returns
    /// Result containing transaction hash if successful, or error
    pub async fn update_did(&self, did: String, document: DIDDocument) -> Result<H256, Box<dyn Error>> {
        let document_json = serde_json::to_string(&document)?;
        self.zksync_client
            .send_transaction(
                &Self::format_address(self.did_registry_address),
                include_bytes!("abi/DIDRegistry.json"),
                "updateDID",
                (did, document_json),
            )
            .await
    }

    /// Issues a new verifiable credential on blockchain
    ///
    /// # Arguments
    /// * `credential` - VerifiableCredential to issue
    ///
    /// # Returns
    /// Result containing transaction hash if successful, or error
    pub async fn issue_credential(&self, credential: VerifiableCredential) -> Result<H256, Box<dyn Error>> {
        let credential_json = serde_json::to_string(&credential)?;
        self.zksync_client
            .send_transaction(
                &Self::format_address(self.credential_registry_address),
                include_bytes!("abi/CredentialRegistry.json"),
                "issueCredential",
                credential_json,
            )
            .await
    }

    /// Revokes an existing verifiable credential on blockchain
    ///
    /// # Arguments
    /// * `credential_id` - ID of the credential to revoke
    ///
    /// # Returns
    /// Result containing transaction hash if successful, or error
    pub async fn revoke_credential(&self, credential_id: String) -> Result<H256, Box<dyn Error>> {
        self.zksync_client
            .send_transaction(
                &Self::format_address(self.credential_registry_address),
                include_bytes!("abi/CredentialRegistry.json"),
                "revokeCredential",
                credential_id,
            )
            .await
    }
}

impl Clone for CredentialIssuer {
    /// Creates a clone of the CredentialIssuer with shared zkSync client
    fn clone(&self) -> Self {
        Self {
            zksync_client: self.zksync_client.clone(),
            credential_registry_address: self.credential_registry_address,
            did_registry_address: self.did_registry_address,
        }
    }
}