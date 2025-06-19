// src/blockchain/zksync_client.rs
//! zkSync blockchain client implementation.
//!
//! Provides a high-level interface for interacting with zkSync Era blockchain,
//! including transaction sending, contract interactions, and wallet management.

use ethers_contract::BaseContract;
use ethers_core::{
    abi::{Abi, Detokenize, Tokenize},
    types::{Address, H256, U256},
    utils::hex,
};
use k256::{
    ecdsa::SigningKey,
    elliptic_curve::generic_array::GenericArray,
};
use std::{error::Error, sync::Arc};
use zksync_web3_rs::{
    contract::Contract,
    providers::{Middleware, Provider, Http},
    signers::{Signer, Wallet},
    zks_wallet::ZKSWallet,
    middleware::SignerMiddleware,
};

/// zkSync blockchain client for managing wallet and contract interactions.
///
/// This client provides:
/// - Secure wallet management with private key
/// - Transaction sending capabilities
/// - Contract query functionality
/// - zkSync-specific operations
#[derive(Clone)]
pub struct ZkSyncClient {
    /// zkSync RPC provider
    provider: Arc<Provider<Http>>,
    /// zkSync wallet with signing capabilities
    wallet: ZKSWallet<SignerMiddleware<Arc<Provider<Http>>, Wallet<SigningKey>>, SigningKey>,
}

impl ZkSyncClient {
    /// Creates a new zkSync client instance.
    ///
    /// # Arguments
    /// * `rpc_url` - zkSync RPC endpoint URL
    /// * `private_key` - Hex-encoded private key (with or without 0x prefix)
    ///
    /// # Returns
    /// New ZkSyncClient instance or error if initialization fails
    ///
    /// # Errors
    /// Returns error if:
    /// - RPC connection fails
    /// - Private key is invalid
    /// - Chain ID cannot be retrieved
    /// - Wallet initialization fails
    pub async fn new(rpc_url: &str, private_key: &str) -> Result<Self, Box<dyn Error>> {
        let provider = Arc::new(Provider::<Http>::try_from(rpc_url)?);
        let private_key_bytes = hex::decode(private_key)?;
        let signing_key = SigningKey::from_bytes(GenericArray::from_slice(&private_key_bytes))?;

        // Create Ethereum wallet with chain ID
        let chain_id = provider.get_chainid().await?.as_u64();
        let l2_wallet = Wallet::from(signing_key.clone()).with_chain_id(chain_id);
        
        // Create middleware for signer
        let signer_middleware = SignerMiddleware::new(
            provider.clone(),
            l2_wallet.clone()
        );

        // Create ZKSync wallet with signer middleware
        let wallet = ZKSWallet::new(
            l2_wallet,
            None, // L1 wallet
            Some(signer_middleware.clone()), // era provider
            None, // eth provider
        )?;

        Ok(Self { provider, wallet })
    }

    /// Gets the wallet's L2 (zkSync) address.
    ///
    /// # Returns
    /// Ethereum-compatible address of the wallet
    #[allow(dead_code)]
    pub fn get_address(&self) -> Address {
        self.wallet.l2_address()
    }

    /// Sends a transaction to a smart contract.
    ///
    /// # Arguments
    /// * `contract_address` - Address of the target contract
    /// * `abi` - Contract ABI bytes
    /// * `method` - Method name to call
    /// * `params` - Method parameters
    ///
    /// # Returns
    /// Transaction hash of the sent transaction
    ///
    /// # Errors
    /// Returns error if:
    /// - Contract address is invalid
    /// - ABI loading fails
    /// - Method invocation fails
    /// - Transaction sending fails
    ///
    /// # Gas Usage
    /// Uses fixed gas limit of 3,000,000 (adjust based on contract requirements)
    pub async fn send_transaction(
        &self,
        contract_address: &str,
        abi: &[u8],
        method: &str,
        params: impl Tokenize,
    ) -> Result<H256, Box<dyn Error>> {
        let abi = Abi::load(abi)?;
        let base_contract = BaseContract::from(abi);
        let address: Address = contract_address.parse().map_err(|e| format!("Invalid contract address: {}", e))?;
        
        let contract = Contract::new(
            address,
            base_contract,
            self.wallet.get_era_provider()?.clone(),
        );

        contract.method::<_, H256>(method, params)?
            .gas(U256::from(3000000))
            .send()
            .await
            .map(|tx| tx.tx_hash())
            .map_err(Into::into)
    }

    /// Queries a smart contract (read-only operation).
    ///
    /// # Arguments
    /// * `contract_address` - Address of the target contract
    /// * `abi` - Contract ABI bytes
    /// * `method` - Method name to call
    /// * `params` - Method parameters
    ///
    /// # Returns
    /// Decoded return value from the contract call
    ///
    /// # Errors
    /// Returns error if:
    /// - Contract address is invalid
    /// - ABI loading fails
    /// - Method invocation fails
    /// - Return value decoding fails
    pub async fn query_contract<R: Detokenize>(
        &self,
        contract_address: &str,
        abi: &[u8],
        method: &str,
        params: impl Tokenize,
    ) -> Result<R, Box<dyn Error>> {
        let abi = Abi::load(abi)?;
        let base_contract = BaseContract::from(abi);
        let address: Address = contract_address.parse().map_err(|e| format!("Invalid contract address: {}", e))?;
        
        let contract = Contract::new(
            address,
            base_contract,
            self.provider.clone(),
        );

        contract.method::<_, R>(method, params)?
            .call()
            .await
            .map_err(Into::into)
    }

    /// Fetches the Merkle proof for a given credential ID from the CredentialRegistry contract.
    ///
    /// This method queries the `getMerkleProof` function on the specified contract, returning
    /// the Merkle root, path, and indices necessary for zero-knowledge proof generation.
    ///
    /// # Arguments
    /// * `contract_address` - The address of the CredentialRegistry contract (hex string)
    /// * `abi` - The ABI of the CredentialRegistry contract as raw bytes
    /// * `credential_id` - The ID of the credential (as a string) to fetch the proof for
    ///
    /// # Returns
    /// A `Result` containing a tuple `(U256, Vec<U256>, Vec<u8>)` representing:
    /// - Merkle root
    /// - Merkle path (array of sibling nodes)
    /// - Indices (positions at each level, 0 for left, 1 for right)
    ///
    /// # Errors
    /// Returns an error if:
    /// - The contract address is invalid
    /// - The ABI cannot be loaded
    /// - The contract method call fails
    /// - The return data cannot be decoded into the expected type
    #[allow(dead_code)]
    pub async fn get_merkle_proof(
        &self,
        contract_address: &str,
        abi: &[u8],
        credential_id: &str,
    ) -> Result<(U256, Vec<U256>, Vec<u8>), Box<dyn Error>> {
        let (root, path, indices): (U256, Vec<U256>, Vec<u8>) = self.query_contract(
            contract_address,
            abi,
            "getMerkleProof",
            credential_id.to_string(),
        ).await?;
        Ok((root, path, indices))
    }
}