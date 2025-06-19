// src/utils/serialization.rs
//! Serialization utilities for the DID system.
//!
//! Provides serialization and deserialization functions for:
//! - JSON data structures
//! - Cryptographic parameters (Poseidon configurations)
//! - Cross-format conversions

use serde::{Serialize, Deserialize};
use serde_json;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

/// Serializes a value to a JSON string.
///
/// # Arguments
/// * `data` - The value to serialize (must implement `Serialize`)
///
/// # Returns
/// - `Ok(String)` with JSON representation on success
/// - `Err(serde_json::Error)` if serialization fails
pub fn serialize<T: Serialize>(data: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(data)
}

/// Deserializes a value from a JSON string.
///
/// # Arguments
/// * `data` - JSON string to deserialize
///
/// # Returns
/// - `Ok(T)` with deserialized value on success
/// - `Err(serde_json::Error)` if deserialization fails
///
/// # Note
/// The function uses a lifetime parameter to ensure the deserialized value
/// doesn't outlive the input data. This allows borrowing data from the input string.
pub fn deserialize<'a, T: Deserialize<'a>>(data: &'a str) -> Result<T, serde_json::Error> {
    serde_json::from_str(data)
}


/// Serializes a Poseidon configuration to a base64-encoded string.
///
/// # Arguments
/// * `config` - Poseidon configuration for Bn254 field
///
/// # Returns
/// Base64-encoded string representation
///
/// # Panics
/// Panics if serialization fails (should only happen with invalid configurations)
pub fn serialize_poseidon_config(config: &PoseidonConfig<ark_bn254::Fr>) -> String {
    let mut bytes = Vec::new();
    config.serialize_compressed(&mut bytes)
        .expect("Poseidon config serialization failed");
    base64::encode(bytes)
}

/// Deserializes a Poseidon configuration from a base64-encoded string.
///
/// # Arguments
/// * `data` - Base64-encoded configuration string
///
/// # Returns
/// Reconstructed Poseidon configuration
///
/// # Panics
/// Panics if:
/// - Base64 decoding fails
/// - Deserialization fails
pub fn deserialize_poseidon_config(data: &str) -> Result<PoseidonConfig<ark_bn254::Fr>, String> {
    let bytes = base64::decode(data)
        .map_err(|e| format!("Base64 decoding failed: {}", e))?;
    CanonicalDeserialize::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("Deserialization failed: {}", e))
}