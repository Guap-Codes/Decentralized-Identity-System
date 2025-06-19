// src/services/api_server.rs
//! API Server for the Decentralized Identity System
//!
//! This module provides the REST API interface for interacting with the DID system,
//! including DID management, credential operations, zero-knowledge proof generation,
//! wallet management, IPFS document storage, and transaction sponsorship.
//!
//! The API is built using Axum and includes endpoints for:
//! - DID creation, resolution, and updates
//! - Verifiable credential issuance, revocation, and verification
//! - Zero-knowledge proof generation and verification
//! - Wallet creation and message signing
//! - Document storage and retrieval via IPFS
//! - Transaction sponsorship using zkSync paymaster
//! - Batch operations and cross-chain verification

use crate::zkp::proof_generation::{generate_proof, get_poseidon_config};
use crate::zkp::proof_verification::verify_proof;
use crate::wallet::zkp_generation::generate_credential_proof;
use crate::services::credential_issuer::CredentialIssuer;
use crate::services::verifier::Verifier;
use crate::models::credential::VerifiableCredential;
use crate::models::did::DIDDocument;
use crate::blockchain::zksync_client::ZkSyncClient;
use crate::storage::ipfs_client::IpfsStorage;
use crate::wallet::key_management::KeyManager;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use zksync_web3_rs::utils::{hex, keccak256};
use zksync_web3_rs::types::{Address, U256};
use ark_bn254::Fr as Bn254Fr;
use serde_json::json;

//use axum::debug_handler;

// API request and response structures

/// Request payload for creating a new DID
#[derive(Serialize, Deserialize)]
struct CreateDIDRequest {
    did: String,
    public_key: String,
    service_endpoint: String,
}

/// Response for DID creation operation
#[derive(Serialize, Deserialize)]
struct CreateDIDResponse {
    tx_hash: String,
}

/// Response for DID resolution operation
#[derive(Serialize, Deserialize)]
struct ResolveDIDResponse {
    id: String,
    public_key: String,
    service_endpoint: String,
}

/// Request payload for updating an existing DID
#[derive(Serialize, Deserialize)]
struct UpdateDIDRequest {
    did: String,
    public_key: String,
    service_endpoint: String,
}

/// Response for DID update operation
#[derive(Serialize, Deserialize)]
struct UpdateDIDResponse {
    tx_hash: String,
}

/// Request payload for issuing a verifiable credential
#[derive(Serialize, Deserialize)]
struct IssueCredentialRequest {
    id: String,
    issuer: String,
    subject: String,
    claims: Vec<(String, String)>,
    signature: String,
}

/// Response for credential issuance operation
#[derive(Serialize, Deserialize)]
struct IssueCredentialResponse {
    tx_hash: String,
}

/// Request payload for revoking a credential
#[derive(Serialize, Deserialize)]
struct RevokeCredentialRequest {
    credential_id: String,
}

/// Response for credential revocation operation
#[derive(Serialize, Deserialize)]
struct RevokeCredentialResponse {
    tx_hash: String,
}

/// Request payload for verifying a credential
#[derive(Serialize, Deserialize)]
struct VerifyCredentialRequest {
    credential_id: String,
}

/// Response for credential verification operation
#[derive(Serialize, Deserialize)]
struct VerifyCredentialResponse {
    is_valid: bool,
}

/// Request payload for generating a zero-knowledge proof
#[derive(Serialize, Deserialize)]
struct GenerateProofRequest {
    leaf: u32,
    root: u32,
    path: Vec<u32>,
    indices: Vec<u32>,
}

/// Response containing a generated proof
#[derive(Serialize, Deserialize)]
struct GenerateProofResponse {
    proof: String,
}

/// Request payload for verifying a zero-knowledge proof
#[derive(Serialize, Deserialize)]
struct VerifyProofRequest {
    proof: String,
    public_inputs: Vec<u32>,
}

/// Response for proof verification operation
#[derive(Serialize, Deserialize)]
struct VerifyProofResponse {
    is_valid: bool,
}

/// Response containing a newly created wallet address
#[derive(Serialize, Deserialize)]
struct CreateWalletResponse {
    address: String,
}

/// Request payload for signing a message
#[derive(Serialize, Deserialize)]
struct SignMessageRequest {
    message: String,
}

/// Response containing a message signature
#[derive(Serialize, Deserialize)]
struct SignMessageResponse {
    signature: String,
}

/// Request payload for storing a document on IPFS
#[derive(Serialize, Deserialize)]
struct StoreDocumentRequest {
    document: serde_json::Value,
}

/// Response containing IPFS hash of stored document
#[derive(Serialize, Deserialize)]
struct StoreDocumentResponse {
    ipfs_hash: String,
}

/// Response containing a retrieved document from IPFS
#[derive(Serialize, Deserialize)]
struct RetrieveDocumentResponse {
    document: serde_json::Value,
}


/// Response for transaction sponsorship operation
#[derive(Serialize, Deserialize)]
struct SponsorTransactionResponse {
    tx_hash: String,
}

/// Response containing system audit logs
#[derive(Serialize, Deserialize)]
struct AuditLogResponse {
    logs: Vec<serde_json::Value>,
}

/// Request payload for user authentication
#[derive(Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// Response containing authentication token
#[derive(Serialize, Deserialize)]
struct LoginResponse {
    token: String,
}

/// Request payload for batch credential issuance
#[derive(Serialize, Deserialize)]
struct BatchIssueCredentialsRequest {
    credentials: Vec<VerifiableCredential>,
}

/// Response for batch credential issuance operation
#[derive(Serialize, Deserialize)]
struct BatchIssueCredentialsResponse {
    tx_hash: String,
}

/// Request payload for cross-chain credential verification
#[derive(Serialize, Deserialize)]
struct CrossChainVerifyRequest {
    credential: serde_json::Value,
    chain: String,
}

/// Response for cross-chain verification operation
#[derive(Serialize, Deserialize)]
struct CrossChainVerifyResponse {
    is_valid: bool,
}

/// Request payload for sponsoring a transaction
#[derive(Serialize, Deserialize)]
struct SponsorTransactionRequest {
    to: String,
    value: String, // Hex string
    data: String,  // Hex string
}

// Add request struct
#[derive(Serialize, Deserialize)]
struct StoreCredentialRequest {
    id: String,
    credential: VerifiableCredential,
}

// Add request/response structs
#[derive(Serialize, Deserialize)]
struct GenerateCredentialProofRequest {
    credential_id: String,
}

#[derive(Serialize, Deserialize)]
struct GenerateCredentialProofResponse {
    proof: String,
}

/// API server state containing all service dependencies
pub struct ApiServer {
    /// Service for issuing and managing credentials
    credential_issuer: Arc<CredentialIssuer>,
    
    /// Service for verifying credentials
    verifier: Arc<Verifier>,
    
    /// Service for key management operations
    key_manager: Arc<KeyManager>,
    
    /// Service for IPFS document storage
    ipfs_storage: Arc<IpfsStorage>,
    
    /// Client for interacting with zkSync blockchain
    zksync_client: Arc<ZkSyncClient>,
    
    /// Paymaster contract address for sponsored transactions
    paymaster_address: String,
}

impl ApiServer {
    /// Creates a new instance of the API server
    ///
    /// # Arguments
    /// * `credential_issuer` - Service for credential operations
    /// * `verifier` - Service for credential verification
    /// * `key_manager` - Service for key management
    /// * `ipfs_storage` - Service for IPFS storage
    /// * `zksync_client` - Client for zkSync blockchain
    /// * `paymaster_address` - Address of paymaster contract
    pub fn new(
        credential_issuer: CredentialIssuer,
        verifier: Verifier,
        key_manager: KeyManager,
        ipfs_storage: IpfsStorage,
        zksync_client: Arc<ZkSyncClient>,
        paymaster_address: String,
    ) -> Self {
        ApiServer {
            credential_issuer: Arc::new(credential_issuer),
            verifier: Arc::new(verifier),
            key_manager: Arc::new(key_manager),
            ipfs_storage: Arc::new(ipfs_storage),
            zksync_client,
            paymaster_address,
        }
    }

    /// Starts the API server and begins listening for requests
    ///
    /// # Arguments
    /// * `addr` - Socket address to bind to (e.g., "127.0.0.1:3000")
    pub async fn run(&self, addr: SocketAddr) {
        // Configure all API routes
        let app = Router::new()
            .route("/create-did", post(Self::create_did_handler))
            .route("/resolve-did/:did", get(Self::resolve_did_handler))
            .route("/update-did", put(Self::update_did_handler))
            .route("/issue-credential", post(Self::issue_credential_handler))
            .route("/revoke-credential", post(Self::revoke_credential_handler))
            .route("/verify-credential", post(Self::verify_credential_handler))
            .route("/generate-proof", post(Self::generate_proof_handler))
            .route("/verify-proof", post(Self::verify_proof_handler))
            .route("/create-wallet", post(Self::create_wallet_handler))
            .route("/sign-message", post(Self::sign_message_handler))
            .route("/store-document", post(Self::store_document_handler))
            .route("/retrieve-document/:ipfs_hash", get(Self::retrieve_document_handler))
            .route("/sponsor-transaction", post(Self::sponsor_transaction_handler))
            .route("/audit-log", get(Self::audit_log_handler))
            .route("/login", post(Self::login_handler))
            .route("/batch-issue-credentials", post(Self::batch_issue_credentials_handler))
            .route("/cross-chain-verify", post(Self::cross_chain_verify_handler))
            .route("/store-credential", post(Self::store_credential_handler))
            .route("/get-credential/:id", get(Self::get_credential_handler))
            .route("/count-credentials", get(Self::count_credentials_handler))
            .route("/generate-credential-proof", post(Self::generate_credential_proof_handler))
            .with_state(Arc::new(self.clone()));  // Share the entire ApiServer state

        // Create TCP listener
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        
        // Start serving requests
        axum::serve(listener, app).await.unwrap();
    }

    // =====================
    // DID Management Handlers
    // =====================

    /// Creates a new Decentralized Identifier (DID)
    ///
    /// # Endpoint
    /// POST /create-did
    ///
    /// # Request Body
    /// JSON payload containing DID, public key, and service endpoint
    ///
    /// # Responses
    /// - 200 OK: Returns transaction hash
    /// - 400 Bad Request: Invalid public key format
    /// - 500 Internal Server Error: Blockchain operation failed
    async fn create_did_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<CreateDIDRequest>,
    ) -> impl IntoResponse {
        // Decode hex-encoded public key
        let public_key = match hex::decode(&payload.public_key) {
            Ok(key) => key,
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(CreateDIDResponse { tx_hash: "Invalid hex public key".into() }),
            ),
        };

        // Create DID document
        let document = DIDDocument {
            id: payload.did.clone(),
            public_key,
            service_endpoint: payload.service_endpoint,
        };

        // Store DID on blockchain
        match state.credential_issuer.create_did(document).await {
            Ok(tx_hash) => (
                StatusCode::OK,
                Json(CreateDIDResponse { tx_hash: format!("0x{:x}", tx_hash) }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CreateDIDResponse { tx_hash: format!("Error: {}", e) }),
            ),
        }
    }

    /// Resolves a DID to its document representation
    ///
    /// # Endpoint
    /// GET /resolve-did/:did
    ///
    /// # Parameters
    /// * `did` - DID to resolve (path parameter)
    ///
    /// # Responses
    /// - 200 OK: Returns DID document
    /// - 500 Internal Server Error: Resolution failed
    async fn resolve_did_handler(
        Path(did): Path<String>,
        State(state): State<Arc<ApiServer>>,
    ) -> impl IntoResponse {
        match state.credential_issuer.resolve_did(did).await {
            Ok(document) => {
                let public_key_hex = hex::encode(document.public_key);
                (
                    StatusCode::OK,
                    Json(ResolveDIDResponse {
                        id: document.id,
                        public_key: public_key_hex,
                        service_endpoint: document.service_endpoint,
                    }),
                )
            }
            Err(e) => {
                eprintln!("DID resolution failed: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ResolveDIDResponse {
                        id: String::new(),
                        public_key: String::new(),
                        service_endpoint: String::new(),
                    }),
                )
            }
        }
    }

    /// Updates an existing DID document
    ///
    /// # Endpoint
    /// PUT /update-did
    ///
    /// # Request Body
    /// JSON payload containing updated DID document
    ///
    /// # Responses
    /// - 200 OK: Returns transaction hash
    /// - 400 Bad Request: Invalid public key format
    /// - 500 Internal Server Error: Blockchain operation failed
    async fn update_did_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<UpdateDIDRequest>,
    ) -> impl IntoResponse {
        // Decode hex-encoded public key
        let public_key = match hex::decode(&payload.public_key) {
            Ok(key) => key,
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(UpdateDIDResponse { tx_hash: "Invalid hex public key".into() }),
            ),
        };

        // Create updated DID document
        let document = DIDDocument {
            id: payload.did.clone(),
            public_key,
            service_endpoint: payload.service_endpoint,
        };

        // Update DID on blockchain
        match state.credential_issuer.update_did(payload.did, document).await {
            Ok(tx_hash) => (
                StatusCode::OK,
                Json(UpdateDIDResponse { tx_hash: format!("0x{:x}", tx_hash) }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UpdateDIDResponse { tx_hash: format!("Error: {}", e) }),
            ),
        }
    }

    // =====================
    // Credential Handlers
    // =====================

    /// Issues a new verifiable credential
    ///
    /// # Endpoint
    /// POST /issue-credential
    ///
    /// # Request Body
    /// JSON payload containing credential details and signature
    ///
    /// # Responses
    /// - 200 OK: Returns transaction hash
    /// - 400 Bad Request: Invalid signature format
    /// - 500 Internal Server Error: Blockchain operation failed
    async fn issue_credential_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<IssueCredentialRequest>,
    ) -> impl IntoResponse {
        // Decode hex-encoded signature
        let signature = match hex::decode(&payload.signature) {
            Ok(sig) => sig,
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(IssueCredentialResponse { tx_hash: "Invalid hex signature".into() }),
            ),
        };

        // Create verifiable credential
        let credential = VerifiableCredential {
            id: payload.id,
            issuer: payload.issuer,
            subject: payload.subject,
            claims: payload.claims,
            signature,
        };

        // Issue credential on blockchain
        match state.credential_issuer.issue_credential(credential).await {
            Ok(tx_hash) => (
                StatusCode::OK,
                Json(IssueCredentialResponse { tx_hash: format!("0x{:x}", tx_hash) }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(IssueCredentialResponse { tx_hash: format!("Error: {}", e) }),
            ),
        }
    }

    /// Revokes an existing credential
    ///
    /// # Endpoint
    /// POST /revoke-credential
    ///
    /// # Request Body
    /// JSON payload containing credential ID to revoke
    ///
    /// # Responses
    /// - 200 OK: Returns transaction hash
    /// - 500 Internal Server Error: Blockchain operation failed
    async fn revoke_credential_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<RevokeCredentialRequest>,
    ) -> impl IntoResponse {
        match state.credential_issuer.revoke_credential(payload.credential_id).await {
            Ok(tx_hash) => (
                StatusCode::OK,
                Json(RevokeCredentialResponse { tx_hash: format!("0x{:x}", tx_hash) }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RevokeCredentialResponse { tx_hash: format!("Error: {}", e) }),
            ),
        }
    }

    /// Verifies a credential's validity
    ///
    /// # Endpoint
    /// POST /verify-credential
    ///
    /// # Request Body
    /// JSON payload containing credential ID to verify
    ///
    /// # Responses
    /// - 200 OK: Returns verification status
    /// - 500 Internal Server Error: Verification failed
    async fn verify_credential_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<VerifyCredentialRequest>,
    ) -> impl IntoResponse {
        match state.verifier.verify_credential(payload.credential_id).await {
            Ok(is_valid) => (
                StatusCode::OK,
                Json(VerifyCredentialResponse { is_valid }),
            ),
           Err(e) => {
                eprintln!("Credential verification failed: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(VerifyCredentialResponse { is_valid: false }),
                )
            }
        }
    }

    async fn store_credential_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<StoreCredentialRequest>,
    ) -> impl IntoResponse {
        state.key_manager.store_credential(payload.id, payload.credential);
        StatusCode::OK
    }

    async fn get_credential_handler(
        State(state): State<Arc<ApiServer>>,
        Path(id): Path<String>,
    ) -> impl IntoResponse {
        match state.key_manager.get_credential(&id) {
            Some(cred) => Json(cred).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn count_credentials_handler(
        State(state): State<Arc<ApiServer>>,
    ) -> impl IntoResponse {
        let count = state.key_manager.credential_count();
        Json(json!({ "count": count }))
    }

    // Add handler implementation
    async fn generate_credential_proof_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<GenerateCredentialProofRequest>,
    ) -> impl IntoResponse {
        // Get credential from storage
        let credential = match state.key_manager.get_credential(&payload.credential_id) {
            Some(cred) => cred,
            None => return (
                StatusCode::NOT_FOUND,
                Json(GenerateCredentialProofResponse {
                    proof: "Credential not found".into(),
                }),
            ),
        };

        // Generate proof
        match generate_credential_proof(&credential, &state.zksync_client).await {
            Ok(proof) => (
                StatusCode::OK,
                Json(GenerateCredentialProofResponse { proof }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GenerateCredentialProofResponse {
                    proof: format!("Error: {}", e),
                }),
            ),
        }
    }

    // =====================
    // ZKP Handlers
    // =====================

    /// Generates a zero-knowledge proof
    ///
    /// # Endpoint
    /// POST /generate-proof
    ///
    /// # Request Body
    /// JSON payload containing proof parameters
    ///
    /// # Responses
    /// - 200 OK: Returns generated proof
    /// - 500 Internal Server Error: Proof generation failed
    async fn generate_proof_handler(
        Json(payload): Json<GenerateProofRequest>,
    ) -> impl IntoResponse {
        // Remove poseidon_config lookup - no longer needed
        match generate_proof(payload.leaf, payload.root, payload.path, payload.indices) {
            Ok(proof) => (
                StatusCode::OK,
                Json(GenerateProofResponse { proof }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GenerateProofResponse { proof: format!("Error: {}", e) }),
            ),
        }
    }

    /// Verifies a zero-knowledge proof
    ///
    /// # Endpoint
    /// POST /verify-proof
    ///
    /// # Request Body
    /// JSON payload containing proof and public inputs
    ///
    /// # Responses
    /// - 200 OK: Returns verification result
    /// - 500 Internal Server Error: Verification failed
    async fn verify_proof_handler(
        Json(payload): Json<VerifyProofRequest>,
    ) -> impl IntoResponse {
        // Convert public inputs to field elements
        let public_inputs_fr: Vec<Bn254Fr> = payload.public_inputs
            .into_iter()
            .map(Bn254Fr::from)
            .collect();

        // Get the Poseidon configuration
        let poseidon_config = get_poseidon_config();
        
        match verify_proof(&payload.proof, public_inputs_fr, poseidon_config) {
            Ok(is_valid) => (
                StatusCode::OK,
                Json(VerifyProofResponse { is_valid }),
            ),
            Err(e) => {
                eprintln!("Proof verification failed: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(VerifyProofResponse { is_valid: false }),
                )
            }
        }
    }

    // =====================
    // Wallet Handlers
    // =====================

    /// Creates a new cryptographic wallet
    ///
    /// # Endpoint
    /// POST /create-wallet
    ///
    /// # Responses
    /// - 200 OK: Returns wallet address
    /// - 500 Internal Server Error: Key generation failed
    async fn create_wallet_handler(
        State(state): State<Arc<ApiServer>>,
    ) -> impl IntoResponse {
        //let key_manager = KeyManager::new();
        let key_manager = &state.key_manager;
        
        // Convert public key to uncompressed SEC1 format
        let public_key_bytes = key_manager.public_key.to_sec1_bytes();
        
        // Validate public key format
        if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CreateWalletResponse { 
                    address: "Invalid public key format".into() 
                }),
            );
        }
        
        // Extract raw public key (without prefix)
        let raw_public_key = &public_key_bytes[1..];
        
        // Compute Ethereum address
        let hash = keccak256(raw_public_key);
        let address_bytes = &hash[12..];
        let address = Address::from_slice(address_bytes);
        
        (
            StatusCode::OK,
            Json(CreateWalletResponse { 
                address: format!("0x{}", hex::encode(address.as_bytes())) 
            }),
        )
    }

    /// Signs a message with the wallet's private key
    ///
    /// # Endpoint
    /// POST /sign-message
    ///
    /// # Request Body
    /// JSON payload containing message to sign
    ///
    /// # Responses
    /// - 200 OK: Returns signature
    async fn sign_message_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<SignMessageRequest>,
    ) -> impl IntoResponse {
        let signature = state.key_manager.sign_message(payload.message.as_bytes());
        let signature_hex = hex::encode(signature);

        (
            StatusCode::OK,
            Json(SignMessageResponse { 
                signature: signature_hex 
            }),
        )
    }

    // =====================
    // IPFS Handlers
    // =====================

    /// Stores a document on IPFS
    ///
    /// # Endpoint
    /// POST /store-document
    ///
    /// # Request Body
    /// JSON payload containing document to store
    ///
    /// # Responses
    /// - 200 OK: Returns IPFS hash
    /// - 400 Bad Request: Invalid JSON document
    /// - 500 Internal Server Error: IPFS operation failed
    //#[debug_handler(state = Arc<ApiServer>)]
    async fn store_document_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<StoreDocumentRequest>,
    ) -> impl IntoResponse {
        // Use the new JSON storage method
        match state.ipfs_storage.store_json(&payload.document).await {
            Ok(ipfs_hash) => (
                StatusCode::OK,
                Json(StoreDocumentResponse { ipfs_hash }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(StoreDocumentResponse {
                    ipfs_hash: format!("Error: {}", e),
                }),
            ),
        }
    }

    /// Retrieves a document from IPFS
    ///
    /// # Endpoint
    /// GET /retrieve-document/:ipfs_hash
    ///
    /// # Parameters
    /// * `ipfs_hash` - IPFS content hash (path parameter)
    ///
    /// # Responses
    /// - 200 OK: Returns document content
    /// - 404 Not Found: Document not found
    /// - 500 Internal Server Error: Invalid document format
    async fn retrieve_document_handler(
        State(state): State<Arc<ApiServer>>,
        Path(ipfs_hash): Path<String>,
    ) -> impl IntoResponse {
        // Use the new JSON retrieval method
        match state.ipfs_storage.retrieve_json(&ipfs_hash).await {
            Ok(document) => (
                StatusCode::OK,
                Json(RetrieveDocumentResponse { document }),
            ),
            Err(e) => (
                StatusCode::NOT_FOUND,
                Json(RetrieveDocumentResponse {
                    document: serde_json::json!({
                        "error": format!("Document not found: {}", e)
                    }),
                }),
            ),
        }
    }
   
    // =====================
    // Transaction Sponsorship
    // =====================

    /// Sponsors a transaction using the paymaster contract
    ///
    /// # Endpoint
    /// POST /sponsor-transaction
    ///
    /// # Request Body
    /// JSON payload containing transaction details
    ///
    /// # Responses
    /// - 200 OK: Returns transaction hash
    /// - 500 Internal Server Error: Transaction failed
    /// Request payload for sponsoring a transaction
    async fn sponsor_transaction_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<SponsorTransactionRequest>,
    ) -> impl IntoResponse {
        // Parse address
        let to = match payload.to.parse::<Address>() {
            Ok(addr) => addr,
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(SponsorTransactionResponse { 
                    tx_hash: "Invalid address format".into() 
                }),
            ),
        };

        // Parse value
        let value = match U256::from_str_radix(&payload.value.trim_start_matches("0x"), 16) {
            Ok(val) => val,
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(SponsorTransactionResponse { 
                    tx_hash: "Invalid value format".into() 
                }),
            ),
        };

        // Parse data
        let data = match hex::decode(&payload.data.trim_start_matches("0x")) {
            Ok(bytes) => bytes,
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(SponsorTransactionResponse { 
                    tx_hash: "Invalid data format".into() 
                }),
            ),
        };

        // Load paymaster ABI
        let abi = include_bytes!("abi/Paymaster.json");
        
        // Create parameters tuple that implements Tokenize
        let params = (to, value, data);
        
        // Send sponsored transaction
        match state.zksync_client
            .send_transaction(
                &state.paymaster_address,
                abi,
                "sponsorTransaction",
                params,
            )
            .await
        {
            Ok(tx_hash) => (
                StatusCode::OK,
                Json(SponsorTransactionResponse { 
                    tx_hash: format!("0x{:x}", tx_hash) 
                }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SponsorTransactionResponse { 
                    tx_hash: format!("Error: {}", e) 
                }),
            )
        }
    }
  
    // =====================
    // Audit & Security
    // =====================

    /// Retrieves system audit logs
    ///
    /// # Endpoint
    /// GET /audit-log
    ///
    /// # Responses
    /// - 200 OK: Returns audit logs
    async fn audit_log_handler(
        State(_state): State<Arc<ApiServer>>,
    ) -> impl IntoResponse {
        // Placeholder implementation - integrate with real audit system
        let logs = vec![serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event": "system_check",
            "status": "ok"
        })];

        (
            StatusCode::OK,
            Json(AuditLogResponse { logs }),
        )
    }

    /// Authenticates a user and returns an access token
    ///
    /// # Endpoint
    /// POST /login
    ///
    /// # Request Body
    /// JSON payload containing username and password
    ///
    /// # Responses
    /// - 200 OK: Returns authentication token
    /// - 401 Unauthorized: Invalid credentials
    async fn login_handler(
        State(_state): State<Arc<ApiServer>>,
        Json(payload): Json<LoginRequest>,
    ) -> impl IntoResponse {
        // Placeholder authentication - integrate with real auth system
        if payload.username == "admin" && payload.password == "securepassword" {
            let token = "placeholder-jwt-token".to_string();
            (
                StatusCode::OK,
                Json(LoginResponse { token }),
            )
        } else {
            (
                StatusCode::UNAUTHORIZED,
                Json(LoginResponse { token: String::new() }),
            )
        }
    }

    // =====================
    // Batch Operations
    // =====================

    /// Issues multiple credentials in a batch operation
    ///
    /// # Endpoint
    /// POST /batch-issue-credentials
    ///
    /// # Request Body
    /// JSON payload containing list of credentials
    ///
    /// # Responses
    /// - 200 OK: Returns batch completion status
    /// - 500 Internal Server Error: Batch operation failed
    async fn batch_issue_credentials_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<BatchIssueCredentialsRequest>,
    ) -> impl IntoResponse {
        let mut tx_hashes = Vec::new();
        
        // Process each credential in batch
        for credential in payload.credentials {
            match state.credential_issuer.issue_credential(credential).await {
                Ok(tx_hash) => tx_hashes.push(format!("0x{:x}", tx_hash)),
                Err(e) => return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(BatchIssueCredentialsResponse { 
                        tx_hash: format!("Failed at credential {}: {}", tx_hashes.len(), e)
                    }),
                )
            }
        }

        // Return batch completion status
        (
            StatusCode::OK,
            Json(BatchIssueCredentialsResponse { 
                tx_hash: format!("Batch completed with {} transactions", tx_hashes.len())
            }),
        )
    }

    // =====================
    // Cross-chain Verification
    // =====================

    /// Verifies a credential across different blockchains
    ///
    /// # Endpoint
    /// POST /cross-chain-verify
    ///
    /// # Request Body
    /// JSON payload containing credential and target chain
    ///
    /// # Responses
    /// - 200 OK: Returns verification result
    async fn cross_chain_verify_handler(
        State(state): State<Arc<ApiServer>>,
        Json(payload): Json<CrossChainVerifyRequest>,
    ) -> impl IntoResponse {
        // Placeholder implementation - integrate with cross-chain verification
        let is_valid = state.verifier.verify_credential(
            payload.credential["id"].as_str().unwrap().to_string()
        )
        .await
        .unwrap_or(false);

        (
            StatusCode::OK,
            Json(CrossChainVerifyResponse { is_valid }),
        )
    }
}

// Implement Clone for ApiServer to use with Axum's State
impl Clone for ApiServer {
    fn clone(&self) -> Self {
        ApiServer {
            credential_issuer: Arc::clone(&self.credential_issuer),
            verifier: Arc::clone(&self.verifier),
            key_manager: self.key_manager.clone(),
            ipfs_storage: self.ipfs_storage.clone(),
            zksync_client: self.zksync_client.clone(),
            paymaster_address: self.paymaster_address.clone(),
        }
    }
}
