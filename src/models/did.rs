// src/models/did.rs
//! Decentralized Identifier (DID) data model implementation.
//!
//! Defines the core structure for W3C-compliant DID Documents following the
//! [DID Core Specification](https://www.w3.org/TR/did-core/).

use serde::{Serialize, Deserialize};

/// A DID Document representing a decentralized identity.
///
/// Implements the basic structure of a DID Document according to W3C standards,
/// containing cryptographic material and service endpoints necessary to
/// authenticate and interact with the DID subject.
///
/// # Fields
/// - `id`: The DID string identifier
/// - `public_key`: Cryptographic public key material
/// - `service_endpoint`: URI for interacting with the DID subject
///
///
/// # DID Format
/// The `id` field should follow DID syntax:
/// ```
/// did:<method>:<method-specific-id>
/// ```
///
/// # Public Key Format
/// The `public_key` field contains raw bytes that should be interpreted
/// according to the DID method's specified key format.
///
/// # Service Endpoint
/// The `service_endpoint` should be a valid URI that provides:
/// - DID resolution capabilities
/// - Service discovery
/// - Additional identity operations
///
/// # Security Considerations
/// - DIDs should be resolved through trusted methods
/// - Public keys should be verified against the DID method specification
/// - Service endpoints should use HTTPS with proper authentication
#[derive(Serialize, Deserialize, Debug)]
pub struct DIDDocument {
    /// The complete DID string identifier
    /// Example: "did:example:123456789abcdefghi"
    pub id: String,

    /// Raw public key bytes in format specified by DID method
    /// Example: 32-byte Ed25519 public key
    pub public_key: Vec<u8>,

    /// URI for interacting with the DID subject
    /// Example: "https://example.com/did-ops"
    pub service_endpoint: String,
}