# Decentralized Identity (DID) System

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-informational)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A robust and secure identity management platform built on blockchain technology, incorporating zero-knowledge proofs for privacy-preserving verification, decentralized storage using IPFS, and seamless integration with the zkSync Layer 2 network for scalable and low-cost transactions.

##  ⚠️ Important Notice
This Decentralized Identity (DID) System is experimental software under active development.

    Not audited - Use at your own risk

    Testnets only - Not ready for mainnet

    APIs may change without warning

    No guarantees of security or stability

By using this software, you accept all risks. Always deploy to test environments and never use with real assets or sensitive data.


## Key Features

- 🪪 **DID Management**
  - Create, resolve, and update decentralized identifiers
  - Securely store DID documents on blockchain

- 🔐 **Verifiable Credentials**
  - Issue, revoke, and verify credentials
  - Batch credential operations

- 🔮 **Zero-Knowledge Proofs**
  - Generate and verify Merkle membership proofs
  - Privacy-preserving credential verification

- 💼 **Wallet Management**
  - Cryptographic key generation
  - Message signing and verification

- 🌐 **IPFS Integration**
  - Store and retrieve documents on IPFS
  - Content-based addressing

- ⛽ **Transaction Sponsorship**
  - Gasless transactions via paymaster

- 🔍 **Cross-Chain Verification**
  - Verify credentials across different blockchains

## Technology Stack
```bash

| Component             | Technology                          |
|-----------------------|-------------------------------------|
| **Blockchain**        | zkSync Era (Ethereum L2)            |
| **Backend**           | Rust (Axum framework)               |
| **Cryptography**      | BN254 curve, Poseidon hashing       |
| **Storage**           | IPFS (InterPlanetary File System)   |
| **Zero-Knowledge**    | Groth16 zk-SNARKs                   |
| **Key Management**    | secp256k1 with Keccak-256           |
| **Smart Contracts**   | Solidity (Foundry)                  |
```


## Getting Started

### Prerequisites

- Rust 1.70+
- Node.js 18+
- IPFS node (local or Infura)
- zkSync testnet account
- Foundry (for contracts)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Guap-Codes/Decentralized-Identity-System.git
   cd Decentralized-Identity-System```

2. Install dependencies:
  ```bash
    cargo build --release
```

3. Set up environment:
```bash
    cp .env.example .env
    # Update values in .env
```

### Smart Contract Setup
1. Install Foundry: `curl -L https://foundry.paradigm.xyz | bash`
2. Install dependencies: `forge install`
3. Build: `forge build`


### Configuration

Edit .env file with your credentials:
```bash
PRIVATE_KEY="your_wallet_private_key"
CREDENTIAL_REGISTRY_ADDRESS="0xYourContractAddress"
DID_REGISTRY_ADDRESS="0xYourContractAddress"
PAYMASTER_ADDRESS="0xYourPaymasterAddress"
IPFS_API_URL="http://localhost:5001" # or Infura URL
```

### Running the System

Start the API server:
```bash
cargo run --release
```
Server will run at http://localhost:3000


### API Endpoints

* DID Management
```bash
Endpoint	                | Method   | Description
----------------------------|----------|----------------------
/create-did	                | POST	   | Create new DID
/resolve-did/:did           | GET	   | Resolve DID document
/update-did	                | PUT	   | Update existing DID
```

* Credential Operations
```bash
Endpoint	                | Method   | Description
----------------------------|----------|-----------------------------
/issue-credential	        | POST	   | Issue verifiable credential
/revoke-credential          | POST     | Revoke credential
/verify-credential          | POST	   | Verify credential validity
/batch-issue-credentials    | POST     | Issue multiple credentials
```

* Zero-Knowledge Proofs
```bash
Endpoint	                | Method   | Description
----------------------------|----------|--------------------------
/generate-proof	            | POST	   | Generate ZKP for Merkle proof
/verify-proof	            | POST	   | Verify ZKP
```

* Wallet Management
```bash
Endpoint	                | Method   |  Description
----------------------------|----------|----------------------------
/create-wallet	            | POST	   |  Generate new wallet
/sign-message	            | POST	   |  Sign message with private key
```

* IPFS Storage
```bash
Endpoint	                 | Method	|  Description
-----------------------------|----------|-----------------------------
/store-document	             | POST	    |  Store document on IPFS
/retrieve-document/:ipfs_hash| GET	    |  Retrieve document from IPFS
```

### Smart Contracts

Contracts are located in contracts/ directory:

   * DIDRegistry.sol: Manage DID documents

   * CredentialRegistry.sol: Handle verifiable credentials

   * Paymaster.sol: Sponsor transactions

## Deployment

Install Foundry:
   ``` bash

curl -L https://foundry.paradigm.xyz | bash
foundryup
```
Deploy contracts:
```bash
    cd contracts
    forge build
    forge script script/Deploy.s.sol --rpc-url zkSync-testnet --broadcast
```

## Project Structure
```bash
did-system/
├── contracts/          # Solidity smart contracts
├── src/
│   ├── blockchain/     # zkSync client
│   ├── models/         # Data structures
│   ├── services/       # API server and business logic
│   ├── storage/        # IPFS client
│   ├── utils/          # Cryptographic utilities
│   ├── wallet/         # Key management
│   ├── zkp/            # Zero-knowledge proof implementation
│   └── main.rs         # Application entry point
├── tests/              # Integration tests
├── config/             # Configuration files
├── scripts/            # Deployment and utility scripts
└── .env.example        # Environment configuration template
```

## Contributing

Contributions are welcome! Please follow these steps:

    Fork the repository

    Create your feature branch (git checkout -b feature/your-feature)

    Commit your changes (git commit -am 'Add some feature')

    Push to the branch (git push origin feature/your-feature)

    Open a pull request

## License

This project is licensed under the Apache License 2.0 - see LICENSE for details.

Disclaimer: This is experimental software. Use at your own risk for production systems.
