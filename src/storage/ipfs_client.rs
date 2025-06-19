// src/storage/ipfs_client.rs
//! IPFS storage client for decentralized file storage.
//!
//! Provides thread-safe interaction with IPFS (InterPlanetary File System) for:
//! - Storing and retrieving arbitrary binary data
//! - JSON serialization/deserialization of structured data
//! - Content-addressed storage with cryptographic hashes
//!
//! # Features
//! - Asynchronous operations using Tokio runtime
//! - Thread-safe client with Arc-based sharing
//! - Automatic JSON serialization/deserialization
//! - Streaming data retrieval for large files
//!
//! # Security Considerations
//! - All stored data is public by default (IPFS is a public network)
//! - For private data, encrypt before storage
//! - Hashes are content-addressable and permanent

use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use std::error::Error;
use std::io::Cursor;
use futures::TryStreamExt;
use bytes::BytesMut;
use std::sync::Arc;
use tokio::task;
use crate::utils::serialization::{serialize, deserialize};
use serde::{de::DeserializeOwned, Serialize};


/// Thread-safe IPFS client wrapper with convenience methods.
///
/// Uses `ipfs-api-backend-hyper` under the hood with:
/// - Automatic connection pooling
/// - Async/await support
/// - Streaming for large files
#[derive(Clone)]
pub struct IpfsStorage {
    /// Shared IPFS client instance (thread-safe via Arc)
    client: Arc<IpfsClient>,
}

impl IpfsStorage {
    /// Creates a new IPFS storage client connected to local IPFS node.
    ///
    /// # Defaults
    /// - Connects to `http://localhost:5001`
    /// - Uses default IPFS API configuration
    ///
    /// # Panics
    /// Will panic if local IPFS node is not running (connection errors occur on first operation)
    pub fn new() -> Self {
        IpfsStorage {
            client: Arc::new(IpfsClient::default()),
        }
    }

    /// Stores raw binary data in IPFS.
    ///
    /// # Arguments
    /// * `data` - Binary data to store
    ///
    /// # Returns
    /// `Result<String, Box<dyn Error>>` where:
    /// - `Ok(hash)` contains the CID (Content Identifier) of stored data
    /// - `Err` contains the storage error
    pub async fn store_data(&self, data: &[u8]) -> Result<String, Box<dyn Error>> {
        let client = self.client.clone();
        let data_owned = data.to_vec();

        let res = task::spawn_blocking(move || -> Result<_, Box<dyn Error + Send>> {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| Box::new(e) as Box<dyn Error + Send>)?;
            rt.block_on(async {
                let reader = Cursor::new(data_owned);
                let res = client
                    .add(reader)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn Error + Send>)?;
                Ok(res)
            })
        })
        .await;

        match res {
            Ok(inner) => match inner {
                Ok(value) => Ok(value.hash),
                Err(e) => Err(e as Box<dyn Error>),
            },
            Err(join_err) => Err(Box::new(join_err) as Box<dyn Error>),
        }
    }

    /// Retrieves binary data from IPFS by its CID.
    ///
    /// # Arguments
    /// * `hash` - The CID (Content Identifier) of the data
    ///
    /// # Returns
    /// `Result<Vec<u8>, Box<dyn Error>>` where:
    /// - `Ok(data)` contains the retrieved binary data
    /// - `Err` contains the retrieval error
    pub async fn retrieve_data(&self, hash: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let client = self.client.clone();
        let hash = hash.to_string();

        let data = task::spawn_blocking(move || -> Result<_, Box<dyn Error + Send>> {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| Box::new(e) as Box<dyn Error + Send>)?;
            rt.block_on(async {
                let data = client
                    .cat(&hash)
                    .try_fold(BytesMut::new(), |mut acc, chunk| async move {
                        acc.extend_from_slice(&chunk);
                        Ok(acc)
                    })
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn Error + Send>)?;
                Ok(data)
            })
        })
        .await;

        match data {
            Ok(inner) => match inner {
                Ok(value) => Ok(value.to_vec()),
                Err(e) => Err(e as Box<dyn Error>),
            },
            Err(join_err) => Err(Box::new(join_err) as Box<dyn Error>),
        }
    }

    /// Stores a JSON-serializable object in IPFS.
    ///
    /// # Arguments
    /// * `obj` - Serializable object to store
    ///
    /// # Returns
    /// `Result<String, Box<dyn Error>>` where:
    /// - `Ok(hash)` contains the CID of stored JSON
    /// - `Err` contains serialization or storage error
    pub async fn store_json<T: Serialize>(&self, obj: &T) -> Result<String, Box<dyn Error>> {
        let json_str = serialize(obj)?;
        self.store_data(json_str.as_bytes()).await
    }

    /// Retrieves and deserializes a JSON object from IPFS.
    ///
    /// # Arguments
    /// * `hash` - The CID of the JSON data
    ///
    /// # Returns
    /// `Result<T, Box<dyn Error>>` where:
    /// - `Ok(obj)` contains the deserialized object
    /// - `Err` contains retrieval or deserialization error
    pub async fn retrieve_json<T: DeserializeOwned>(&self, hash: &str) -> Result<T, Box<dyn Error>> {
        let bytes = self.retrieve_data(hash).await?;
        let json_str = String::from_utf8(bytes)?;
        deserialize(&json_str).map_err(|e| e.into())
    }
}