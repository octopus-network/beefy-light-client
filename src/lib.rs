use primitive_types::H256;

pub mod bitfield;
pub mod commitment;
pub mod keccak256;
pub mod mmr;
pub mod simplified_mmr;
pub mod traits;
pub mod validator_set;

use commitment::{Commitment, Signature, SignedCommitment};
use simplified_mmr::{verify_proof, MerkleProof};
use traits::{ValidatorRegistry, ECDSA};
use validator_set::ValidatorSet;

/// A marker struct for validator set merkle tree.
#[derive(Debug)]
pub struct ValidatorSetTree;

/// A marker struct for the MMR.
#[derive(Debug)]
pub struct Mmr;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// [Commitment] can't be imported, cause it's signed by either past or future validator set.
	// InvalidValidatorSetId { expected: ValidatorSetId, got: ValidatorSetId },
	/// [Commitment] can't be imported, cause it's a set transition block and the proof is missing.
	InvalidValidatorSetProof,
	/// [Commitment] is not useful, cause it's made for an older block than we know of.
	///
	/// In practice it's okay for the light client to import such commitments (if the validator set
	/// matches), but it doesn't provide any more value, since the payload is meant to be
	/// cumulative.
	/// It might be useful however, if we want to verify proofs that were generated against this
	/// specific block number.
	// OldBlock {
	//     /// Best block currently known by the light client.
	//     best_known: BlockNumber,
	//     /// Block in the commitment.
	//     got: BlockNumber,
	// },
	/// There are too many signatures in the commitment - more than validators.
	InvalidNumberOfSignatures {
		/// Number of validators in the set.
		expected: usize,
		/// Numbers of signatures in the commitment.
		got: usize,
	},
	/// [SignedCommitment] doesn't have enough valid signatures.
	NotEnoughValidSignatures { expected: usize, got: usize, valid: Option<usize> },
	/// Next validator set has not been provided by any of the previous commitments.
	MissingNextValidatorSetData,
	/// Couldn't verify the proof against MMR root of the latest commitment.
	InvalidMmrProof,
	///
	InvalidSignature,
}

pub struct LightClient {
	mmr_root: H256,
	// validator_set: ValidatorSet,
	// next_validator_set: Option<merkle_tree::Root<ValidatorSetTree>>,
	// last_commitment: Option<Commitment>,
}

impl ValidatorRegistry for LightClient {}
impl ECDSA for LightClient {
	fn recover(&self, hash: H256, signature: Signature) -> Result<H256, Error> {
		// TODO
		Ok(H256::default())
	}
}

impl LightClient {
	pub fn update_state(
		&mut self,
		signed_commitment: SignedCommitment,
		leaf_hash: H256,
		proof: MerkleProof,
	) -> Result<(), Error> {
		let commitment = self.verify_commitment(signed_commitment)?;
		self.verify_leaf(commitment.payload, leaf_hash, proof)?;
		self.mmr_root = commitment.payload;
		Ok(())
	}

	pub fn verify_solochain_message() {}

	pub fn verify_parachain_message() {}

	fn verify_commitment(&self, signed_commitment: SignedCommitment) -> Result<Commitment, Error> {
		let SignedCommitment { commitment, signatures } = signed_commitment;
		let mut expected_validator_set = vec![];
		for signature in signatures.into_iter() {
			if let Some(signature) = signature {
				let result = self.recover(commitment.hash(), signature);
				match result {
					Ok(signer) => {
						expected_validator_set.push(signer);
					}
					Err(_) => {
						return Err(Error::InvalidSignature);
					}
				}
			}
		}

		// TODO: check if expected_validator_set equals validator_set, or is a minimal subset of validator_set
		Ok(commitment)
	}

	fn verify_leaf(
		&self,
		root_hash: H256,
		leaf_hash: H256,
		proof: MerkleProof,
	) -> Result<(), Error> {
		let result = verify_proof(root_hash, leaf_hash, proof);
		if !result {
			return Err(Error::InvalidMmrProof);
		}
		Ok(())
	}
}
//
// pub fn new() -> LightClient {
//     LightClient {
//         validator_set: (0, vec![validator_set::Public(0)]),
//         next_validator_set: None,
//         last_commitment: None,
//     }
// }
//
// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//         assert_eq!(2 + 2, 4);
//     }
// }
//
