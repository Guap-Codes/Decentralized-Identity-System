// src/wallet/zkp_generation.rs
//! Zero-Knowledge Proof (ZKP) generation for Verifiable Credentials.
//!
//! This module provides functionality to generate cryptographic proofs for credentials
//! without revealing sensitive information. Uses zk-SNARKs to prove knowledge of
//! credential attributes while maintaining privacy.

use crate::zkp::proof_generation::generate_proof;
use crate::models::credential::VerifiableCredential;
use crate::blockchain::zksync_client::ZkSyncClient;
use std::fs;
use std::convert::TryInto;
use std::env;

/// Generates a zero-knowledge proof for a Verifiable Credential.
///
/// This function creates a proof that:
/// - The credential exists in the system (via Merkle tree membership)
/// - The credential has valid attributes
/// - Without revealing the actual credential contents
///
/// # Arguments
/// * `credential` - Reference to the VerifiableCredential to prove
/// * `client` - Reference to the ZkSyncClient for blockchain interactions
///
/// # Returns
/// A `Result` containing a `String` with the serialized proof (format depends on backend)
///
/// # Errors
/// Returns an error if:
/// - The credential ID cannot be parsed as a u32
/// - The ABI file cannot be read
/// - Fetching the Merkle proof fails
/// - Proof generation fails
/// - Merkle root or path elements exceed u32 range
///
/// # Notes
/// - The contract address and ABI path are hardcoded for simplicity. In a production
///   environment, these should be loaded from a configuration file or environment variables.
pub async fn generate_credential_proof(
    credential: &VerifiableCredential,
    client: &ZkSyncClient,
) -> Result<String, Box<dyn std::error::Error>> {
    // Load contract address from environment
    let contract_address = env::var("CREDENTIAL_REGISTRY_ADDRESS")
        .map_err(|_| "CREDENTIAL_REGISTRY_ADDRESS not set in .env file")?;

    // Path to the ABI file
    let abi_path = "services/abi/CredentialRegistry.json";
    let abi_bytes = fs::read(abi_path)?;

    // Parse credential ID as u32 for the Merkle leaf
    let leaf = credential.id
        .parse::<u32>()
        .map_err(|e| format!("Failed to parse credential ID as u32: {}", e))?;

    // Fetch Merkle proof from the blockchain
    let (root, path, indices) = client.get_merkle_proof(&contract_address, &abi_bytes, &credential.id).await?;

    // Convert types to match generate_proof expectations
    let root_u32: u32 = root.try_into().map_err(|_| "Merkle root exceeds u32 range")?;

    let path_u32: Vec<u32> = path
        .into_iter()
        .map(|x| x.try_into().map_err(|_| "Merkle path element exceeds u32 range"))
        .collect::<Result<Vec<u32>, _>>()?;
    let indices_u32: Vec<u32> = indices
        .into_iter()
        .map(|x| x as u32)
        .collect();

    // Generate the ZKP
    let proof = generate_proof(leaf, root_u32, path_u32, indices_u32)
        .map_err(|e| format!("Proof generation failed: {}", e))?;

    Ok(proof)
}