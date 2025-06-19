// src/models/credential.rs
//! Verifiable Credential data model implementation.
//!
//! Defines the core structure for W3C-compliant Verifiable Credentials (VCs)
//! with support for JSON serialization and cryptographic signatures.

use serde::{Serialize, Deserialize};

/// A Verifiable Credential according to W3C standards.
///
/// Represents a tamper-evident credential that can be cryptographically verified.
/// Implements basic structure following the [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/).
///
/// # Fields
/// - `id`: Unique identifier URI for the credential
/// - `issuer`: DID of the issuing entity
/// - `subject`: DID of the credential subject
/// - `claims`: Key-value pairs of credential claims
/// - `signature`: Cryptographic proof of credential integrity
///
///
/// # Serialization
/// The struct supports both JSON serialization and deserialization
/// through Serde's derive macros.
///
/// # Security Considerations
/// - The `signature` field should be generated using proper cryptographic signing
/// - All DIDs should be properly resolved before verification
/// - Claims should be validated against expected schemas
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifiableCredential {
    /// Unique URI identifier for the credential
    /// Example: "urn:uuid:123e4567-e89b-12d3-a456-426614174000"
    pub id: String,

    /// DID of the credential issuer
    /// Example: "did:example:issuer"
    pub issuer: String,

    /// DID of the credential subject
    /// Example: "did:example:subject"
    pub subject: String,

    /// Credential claims as key-value pairs
    /// Example: [("degreeType", "BachelorDegree"), ("degreeSchool", "Example University")]
    pub claims: Vec<(String, String)>,

    /// Digital signature proving credential authenticity
    /// Format depends on the signature scheme used
    /// Example: ECDSA signature bytes
    pub signature: Vec<u8>,
}