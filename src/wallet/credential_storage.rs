// src/wallet/credential_storage.rs
//! Credential storage management for the wallet component.
//!
//! Provides an in-memory storage system for managing Verifiable Credentials (VCs)
//! within the DID wallet. This implementation uses a hashmap for efficient lookup
//! and storage of credentials by their unique identifiers.

use crate::models::credential::VerifiableCredential;
use std::collections::HashMap;

/// In-memory storage for Verifiable Credentials.
///
/// This storage provides:
/// - Thread-unsafe in-memory credential storage (for single-threaded contexts)
/// - O(1) average case complexity for insertions and lookups
/// - Simple credential management interface
///
/// # Note
/// For production use, consider persisting to secure storage or database.
pub struct CredentialStorage {
    /// Internal hashmap storing credentials by their ID
    credentials: HashMap<String, VerifiableCredential>,
}

#[allow(dead_code)]
impl CredentialStorage {
    /// Creates a new empty CredentialStorage instance.
    ///
    /// # Returns
    /// New empty CredentialStorage
    pub fn new() -> Self {
        CredentialStorage { 
            credentials: HashMap::new() 
        }
    }

    /// Stores a Verifiable Credential in the wallet.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the credential
    /// * `credential` - The VerifiableCredential to store
    ///
    /// # Behavior
    /// - Overwrites existing credential if ID already exists
    /// - Does not validate credential before storage
    pub fn store_credential(&mut self, id: String, credential: VerifiableCredential) {
        self.credentials.insert(id, credential);
    }

    /// Retrieves a Verifiable Credential by its ID.
    ///
    /// # Arguments
    /// * `id` - The credential identifier to look up
    ///
    /// # Returns
    /// - `Some(&VerifiableCredential)` if found
    /// - `None` if credential doesn't exist
    ///
    /// # Note
    /// Returns a reference to avoid ownership transfer
    pub fn get_credential(&self, id: &str) -> Option<&VerifiableCredential> {
        self.credentials.get(id)
    }

    /// Returns the number of stored credentials.
    ///
    /// # Returns
    /// usize representing the count of stored credentials
    pub fn count_credentials(&self) -> usize {
        self.credentials.len()
    }

    /// Checks if a credential with the specified ID exists in storage.
    ///
    /// # Arguments
    /// * `id` - The credential identifier to check
    ///
    /// # Returns
    /// `true` if a credential with the given ID exists, `false` otherwise.
    ///
    /// # Performance
    /// - O(1) average time complexity (hash-based lookup)
    /// - More efficient than `get_credential` when only existence check is needed
    pub fn contains_credential(&self, id: &str) -> bool {
        self.credentials.contains_key(id)
    }

    /// Removes a credential from storage by its ID.
    ///
    /// # Arguments
    /// * `id` - The credential identifier to remove
    ///
    /// # Returns
    /// `true` if the credential was present and removed, `false` if no credential
    /// was found with the specified ID.
    ///
    /// # Side Effects
    /// - Permanently removes the credential from storage
    /// - Reduces credential count by one if credential existed
    ///
    /// # Security Note
    /// - Does not perform cryptographic shredding of memory
    /// - Actual credential data may remain in memory until overwritten
    pub fn remove_credential(&mut self, id: &str) -> bool {
        self.credentials.remove(id).is_some()
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::credential::VerifiableCredential;

    fn create_test_credential(id: &str) -> VerifiableCredential {
        VerifiableCredential::new(id.to_string())
    }

    #[test]
    fn test_contains_credential() {
        let mut storage = CredentialStorage::new();
        let credential_id = "education-degree-123";
        
        // Initially should not contain
        assert!(!storage.contains_credential(credential_id));
        
        // Add and verify exists
        storage.store_credential(
            credential_id.to_string(),
            create_test_credential(credential_id)
        );
        assert!(storage.contains_credential(credential_id));
    }

    #[test]
    fn test_remove_credential() {
        let mut storage = CredentialStorage::new();
        let credential_id = "temporary-access-pass";
        
        // Add credential
        storage.store_credential(
            credential_id.to_string(),
            create_test_credential(credential_id)
        );
        
        // Remove and verify
        assert!(storage.remove_credential(credential_id));
        assert!(!storage.contains_credential(credential_id));
        assert_eq!(storage.count_credentials(), 0);
        
        // Remove non-existent returns false
        assert!(!storage.remove_credential("non-existent-id"));
    }

    #[test]
    fn test_count_after_operations() {
        let mut storage = CredentialStorage::new();
        
        // Add credentials
        storage.store_credential("id1".to_string(), create_test_credential("id1"));
        storage.store_credential("id2".to_string(), create_test_credential("id2"));
        assert_eq!(storage.count_credentials(), 2);
        
        // Remove one
        storage.remove_credential("id1");
        assert_eq!(storage.count_credentials(), 1);
        
        // Add duplicate ID (overwrite)
        storage.store_credential("id2".to_string(), create_test_credential("id2"));
        assert_eq!(storage.count_credentials(), 1);
    }

    #[test]
    fn test_get_after_remove() {
        let mut storage = CredentialStorage::new();
        let credential_id = "membership-card";
        
        storage.store_credential(
            credential_id.to_string(),
            create_test_credential(credential_id)
        );
        storage.remove_credential(credential_id);
        
        assert!(storage.get_credential(credential_id).is_none());
    }
}