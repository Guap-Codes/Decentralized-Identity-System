// src/utils/crypto.rs
//! Cryptographic utilities optimized for blockchain compatibility.
//!
//! Uses Keccak-256 (Ethereum's standard hash function) for all operations.

use ethers::utils::keccak256;

/// Computes a Keccak-256 hash of the input data (Ethereum-compatible).
///
/// # Arguments
/// * `data` - Binary data to hash (as bytes slice)
///
/// # Returns
/// Fixed-size 32-byte array (`[u8; 32]`) containing the hash.
///
/// # Why Keccak-256?
/// - Ethereum's native hash function (used in Solidity's `keccak256()`)
/// - Compatible with zkSync, smart contracts, and Merkle proofs
/// - Standard for Ethereum signatures and RLP encoding
///
/// # Example
/// ```
/// let hash = hash_data(b"hello world");
/// assert_eq!(hash[..], hex!("..."));
/// ```
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    keccak256(data)
}