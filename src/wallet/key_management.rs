// src/wallet/key_management.rs
//! Cryptographic key management for the DID wallet.
//!
//! Provides secure generation, storage, and usage of cryptographic keys for:
//! - Digital signatures
//! - Key derivation
//! - Identity verification
//!
//! Uses the following cryptographic primitives:
//! - secp256k1 curve (via `k256` crate)
//! - Keccak-256 hashing (via `ethers` crate)
//! - Cryptographically secure random number generation

use k256::{PublicKey, SecretKey};
use k256::ecdsa::{Signature, SigningKey};
use k256::ecdsa::signature::hazmat::PrehashSigner; // Added for sign_prehash
use ark_std::rand;
use crate::models::credential::VerifiableCredential;
use crate::wallet::credential_storage::CredentialStorage;
use crate::utils::crypto::hash_data;
use std::sync::{Arc, Mutex};

/// Secure key management system for elliptic curve cryptography.
///
/// This struct provides:
/// - Secure key generation using system RNG
/// - Public key derivation
/// - Message signing capabilities
/// - Thread-safe cloning of key material
///
/// # Security Notes
/// - Secret keys are never exposed publicly
/// - Uses cryptographically secure random number generation
/// - Implements proper signature schemes (ECDSA)
#[derive(Clone)]
pub struct KeyManager {
    /// Securely stored private key (never exposed)
    secret_key: SecretKey,
    /// Derived public key for verification
    pub public_key: PublicKey,

    credential_storage: Arc<Mutex<CredentialStorage>>,
}

#[allow(dead_code)]
impl KeyManager {
    /// Generates a new KeyManager with fresh cryptographic keys.
    ///
    /// # Returns
    /// New KeyManager instance containing:
    /// - Randomly generated secp256k1 private key
    /// - Derived public key
    ///
    /// # Panics
    /// May panic if:
    /// - System RNG fails
    /// - Key generation fails (extremely unlikely)
    pub fn new() -> Self {
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let public_key = secret_key.public_key();
        KeyManager { 
            secret_key, 
            public_key,
            credential_storage: Arc::new(Mutex::new(CredentialStorage::new())), 
        }
    }

    /// Signs a message using ECDSA (secp256k1) with Keccak-256 prehashing.
    ///
    /// # Arguments
    /// * `message` - Raw message bytes to sign
    ///
    /// # Returns
    /// 64-byte compact ECDSA signature (R || S values)
    ///
    /// # Process Flow
    /// 1. Hashes message with Keccak-256
    /// 2. Signs the hash using ECDSA
    /// 3. Serializes signature in compact format
    ///
    /// # Security
    /// - Uses deterministic ECDSA (RFC 6979)
    /// - Includes message hashing to prevent malleability
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        // Hash message using Keccak-256 (Ethereum standard)
        let hash = hash_data(message);
        
        // Convert to signing key
        let signing_key = SigningKey::from(&self.secret_key);
        
        // Create ECDSA signature
        let signature: Signature = signing_key
            .sign_prehash(&hash)
            .expect("Failed to sign message hash");
        
        // Serialize to compact format (64 bytes: R || S)
        signature.to_vec()
    }

    
    /// Stores a verifiable credential in the wallet's secure storage.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the credential (e.g., a UUID or DID)
    /// * `credential` - The [`VerifiableCredential`] to store
    ///
    /// # Security Notes
    /// - Credentials are stored in memory-protected storage
    /// - Uses mutex lock for thread-safe access
    /// - Overwrites existing credential if ID already exists
    pub fn store_credential(&self, id: String, credential: VerifiableCredential) {
        let mut storage = self.credential_storage.lock().unwrap();
        storage.store_credential(id, credential);
    }

    /// Retrieves a verifiable credential from the wallet by its ID.
    ///
    /// # Arguments
    /// * `id` - The credential's unique identifier
    ///
    /// # Returns
    /// `Option<VerifiableCredential>` where:
    /// - `Some(credential)` if found
    /// - `None` if no credential exists with that ID
    ///
    /// # Performance
    /// - O(1) lookup time (assuming hash-based storage)
    /// - Returns cloned credential to avoid lock contention
    pub fn get_credential(&self, id: &str) -> Option<VerifiableCredential> {
        let storage = self.credential_storage.lock().unwrap();
        storage.get_credential(id).cloned()
    }

    /// Returns the count of credentials currently stored in the wallet.
    ///
    /// # Returns
    /// `usize` - Number of stored credentials
    ///
    /// # Use Cases
    /// - Wallet capacity monitoring
    /// - Synchronization status checks
    /// - UI progress indicators
    pub fn credential_count(&self) -> usize {
        let storage = self.credential_storage.lock().unwrap();
        storage.count_credentials()
    }

    /// Checks if a credential exists in the wallet without retrieving it.
    /// More efficient than `get_credential` when only existence needs verification.
    pub fn has_credential(&self, id: &str) -> bool {
        let storage = self.credential_storage.lock().unwrap();
        storage.contains_credential(id)
    }

    /// Removes a credential from the wallet.
    /// Returns true if a credential was removed, false if no matching ID was found.
    pub fn remove_credential(&self, id: &str) -> bool {
        let mut storage = self.credential_storage.lock().unwrap();
        storage.remove_credential(id)
    }
}