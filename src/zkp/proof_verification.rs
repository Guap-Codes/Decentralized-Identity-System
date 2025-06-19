// src/zkp/proof_verification.rs
//! # Zero-Knowledge Proof Verification
//!
//! This module provides functionality to verify zk-SNARK proofs for Merkle tree membership
//! using the Groth16 proving system with BN254 curve. The implementation ensures:
//! - Proof integrity verification
//! - Public input consistency
//! - Correct circuit constraint satisfaction
//!
//! ## Cryptographic Components
//! - **Groth16**: zk-SNARK proving system
//! - **BN254**: Elliptic curve pairing
//! - **Poseidon Hash**: Cryptographic sponge function for Merkle tree hashing
//!
//! ## Security Considerations
//! - Always verify proofs against trusted verification keys
//! - Ensure Poseidon parameters match those used in proof generation
//! - Validate public inputs before verification

use ark_groth16::{Groth16, Proof};
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use ark_serialize::CanonicalDeserialize;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use base64;
use std::error::Error;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_crypto_primitives::{
    sponge::{
        poseidon::PoseidonConfig,
    },
    sponge::constraints::CryptographicSpongeVar,
};
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use rand::rngs::OsRng;

/// Verifies a Groth16 zk-SNARK proof for Merkle tree membership
///
/// # Arguments
/// * `proof_base64` - Base64-encoded proof bytes
/// * `public_inputs` - Public inputs to the circuit (Merkle root)
/// * `poseidon_config` - Poseidon hash parameters (must match prover's config)
///
/// # Returns
/// `Result<bool, Box<dyn Error>>` where:
/// - `Ok(true)` if proof is valid
/// - `Ok(false)` if proof is invalid
/// - `Err` if deserialization or verification fails
///
/// # Errors
/// - Base64 decoding failure
/// - Proof deserialization failure
/// - Verification key generation failure
/// - Proof verification failure
pub fn verify_proof(
    proof_base64: &str,
    public_inputs: Vec<Bn254Fr>,
    poseidon_config: PoseidonConfig<Bn254Fr>,
) -> Result<bool, Box<dyn Error>> {
    // Decode proof from Base64
    let proof_bytes = base64::decode(proof_base64)
        .map_err(|e| format!("Base64 decoding failed: {}", e))?;
    
    // Deserialize proof
    let proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes[..])
        .map_err(|e| format!("Proof deserialization failed: {}", e))?;

    let mut rng = OsRng;
 
    // Generate verification key (in production, this should be pre-generated)
    let (_, vk) = {
        let circuit = MerkleProofCircuit {
            leaf: Some(Bn254Fr::from(1)), // Dummy values for setup
            root: Bn254Fr::from(1),
            path: vec![Bn254Fr::from(1)],
            indices: vec![0],
            poseidon_config: poseidon_config.clone(),
        };
        Groth16::<Bn254>::setup(circuit, &mut rng)
            .map_err(|e| format!("Verification key generation failed: {}", e))?
    };

    // Verify proof against public inputs
    Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Circuit for verifying Merkle tree membership proofs
#[derive(Clone)]
struct MerkleProofCircuit<F: PrimeField> {
    /// Leaf being proven (private input)
    pub leaf: Option<F>,
    /// Claimed root hash (public input)
    pub root: F,
    /// Sibling nodes along the Merkle path
    pub path: Vec<F>,
    /// Binary indices indicating path direction (0=left, 1=right)
    pub indices: Vec<u32>,
    /// Poseidon hash parameters
    pub poseidon_config: PoseidonConfig<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MerkleProofCircuit<F> {
    /// Generates R1CS constraints for the Merkle proof verification
    ///
    /// # Constraints
    /// 1. Leaf hash must match the first path element
    /// 2. Each path step must correctly hash with its sibling
    /// 3. Final computed root must match the claimed root
    fn generate_constraints(self, cs_ref: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate leaf as private witness
        let leaf_var = FpVar::new_witness(cs_ref.clone(), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate root as public input
        let root_var = FpVar::new_input(cs_ref.clone(), || Ok(self.root))?;
        let mut current_hash = leaf_var;

        // Process each level of the Merkle path
        for (sibling, index) in self.path.iter().zip(self.indices.iter()) {
            let sibling_var = FpVar::new_witness(cs_ref.clone(), || Ok(*sibling))?;

            // Determine hash order based on path index
            let (left_var, right_var) = if *index == 0 {
                (current_hash.clone(), sibling_var) // Current is left
            } else {
                (sibling_var, current_hash.clone()) // Current is right
            };

            // Compute hash(left || right)
            let mut sponge_var = PoseidonSpongeVar::<F>::new(cs_ref.clone(), &self.poseidon_config);
            let inputs = vec![left_var, right_var];
            sponge_var.absorb(&inputs)?;
            let mut squeezed = sponge_var.squeeze_field_elements(1)?;
            current_hash = squeezed.remove(0);
        }

        // Enforce final hash matches claimed root
        current_hash.enforce_equal(&root_var)?;
        Ok(())
    }
}