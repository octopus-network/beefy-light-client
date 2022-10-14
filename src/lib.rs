#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unnecessary_cast)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use beefy_merkle_tree::{merkle_root, verify_proof, Keccak256};
use borsh::{BorshDeserialize, BorshSerialize};
use codec::Decode;
use commitment::{
	known_payload_ids::MMR_ROOT_ID, Commitment, Signature, SignedCommitment,
};
use header::Header;
use mmr::MmrLeaf;
use validator_set::{BeefyNextAuthoritySet, ValidatorSetId};

pub use beefy_merkle_tree::{Hash, MerkleProof};

pub mod commitment;
pub mod header;
pub mod mmr;
pub mod simplified_mmr;
pub mod validator_set;

pub use commitment::BeefyPayloadId;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// [Commitment] can't be imported, cause it's signed by either past or future validator set.
	InvalidValidatorSetId { expected: ValidatorSetId, got: ValidatorSetId },
	/// [Commitment] can't be imported, cause it's a set transition block and the proof is missing.
	InvalidValidatorProof,
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
	///
	InvalidMessage,
	///
	InvalidVersionedFinalityProof,
	///
	InvalidCommitmentPayload,
	///
	InvalidRecoveryId,
	///
	WrongSignature,
	///
	InvalidMmrLeafProof,
	///
	DigestNotFound,
	///
	DigestNotMatch,
	///
	HeaderHashNotMatch,
	///
	CantDecodeHeader,
	///
	CantDecodeMmrLeaf,
	///
	CantDecodeMmrProof,
	///
	MissingLatestCommitment,
	///
	CommitmentAlreadyUpdated,
	///
	ValidatorNotFound,
	///
	MissingInProcessState,
}

/// Convert BEEFY secp256k1 public keys into Ethereum addresses
pub fn beefy_ecdsa_to_ethereum(compressed_key: &[u8]) -> Vec<u8> {
	libsecp256k1::PublicKey::parse_slice(
		compressed_key,
		Some(libsecp256k1::PublicKeyFormat::Compressed),
	)
	// uncompress the key
	.map(|pub_key| pub_key.serialize().to_vec())
	// now convert to ETH address
	.map(|uncompressed| Keccak256::hash(&uncompressed[1..])[12..].to_vec())
	.unwrap_or_default()
}

#[derive(Debug, Default, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct ValidatorMerkleProof {
	/// Proof items (does not contain the leaf hash, nor the root obviously).
	///
	/// This vec contains all inner node hashes necessary to reconstruct the root hash given the
	/// leaf hash.
	pub proof: Vec<Hash>,
	/// Number of leaves in the original tree.
	///
	/// This is needed to detect a case where we have an odd number of leaves that "get promoted"
	/// to upper layers.
	pub number_of_leaves: usize,
	/// Index of the leaf the proof is for (0-based).
	pub leaf_index: usize,
	/// Leaf content.
	pub leaf: Vec<u8>,
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct InProcessState {
	pub position: usize,
	commitment_hash: Hash,
	signed_commitment: SignedCommitment,
	validator_proofs: Vec<ValidatorMerkleProof>,
	validator_set: BeefyNextAuthoritySet,
}

#[derive(Debug, Default, BorshDeserialize, BorshSerialize)]
pub struct LightClient {
	pub latest_commitment: Option<Commitment>,
	pub validator_set: BeefyNextAuthoritySet,
	pub in_process_state: Option<InProcessState>,
}

impl LightClient {
	// Initialize light client using the BeefyId of the initial validator set.
	pub fn new(initial_public_keys: Vec<String>) -> Self {
		let initial_public_keys: Vec<Vec<u8>> = initial_public_keys
			.into_iter()
			.map(|hex_str| {
				hex::decode(&hex_str[2..])
					.map(|compressed_key| beefy_ecdsa_to_ethereum(&compressed_key))
					.unwrap_or_default()
			})
			.collect();

		Self {
			latest_commitment: None,
			validator_set: BeefyNextAuthoritySet {
				id: 0,
				len: initial_public_keys.len() as u32,
				root: merkle_root::<Keccak256, _, _>(initial_public_keys),
			},
			in_process_state: None,
		}
	}

	fn verify_mmr_leaf(
		&self,
		signed_commitment: &[u8],
		mmr_leaf: &[u8],
		mmr_proof: &[u8],
	) -> Result<(MmrLeaf, SignedCommitment), Error> {
		// Deserlized vector<u8> signed_commitment to SignedCommitment
		let signed_commitment = SignedCommitment::decode(&mut &signed_commitment[..])
			.map_err(|_| Error::InvalidVersionedFinalityProof)?;

		// check LightClient's latest commitment with signed commitment
		// if LightClient's commitment `>` SignedCommitment's commitment
		// LightClient'a Commitment have already updated(Error::COmmitmentAlreadyUpdated)
		if let Some(latest_commitment) = &self.latest_commitment {
			if signed_commitment.commitment <= *latest_commitment {
				return Err(Error::CommitmentAlreadyUpdated)
			}
		}

		// Get all signature from signed_commitment
		let signatures_count =
			signed_commitment.signatures.iter().filter(|&sig| sig.is_some()).count();
		// Compatr LightClient's validator set length with Signatures Count
		// signatures length `<` a half of LightClient's validator set length
		// will report this error(InvalidNumberOfSignatures)
		if signatures_count < (self.validator_set.len / 2) as usize {
			return Err(Error::InvalidNumberOfSignatures {
				expected: (self.validator_set.len / 2) as usize,
				got: signatures_count,
			})
		}

		// get mmr root from commitment palyload
		let mmr_root: [u8; 32] = signed_commitment
			.commitment
			.clone()
			.payload
			.get_decoded(&MMR_ROOT_ID)
			.ok_or(Error::InvalidCommitmentPayload)?;
		// Deserlized MmrLeafProof from mmr_proof(Vector<u8>)
		let mmr_proof = mmr::MmrLeafProof::decode(&mut &mmr_proof[..])
			.map_err(|_| Error::CantDecodeMmrProof)?;
		// Deserlized MmrLeaf from mmr_leaf(Vector<u8>)
		let mmr_leaf: Vec<u8> =
			Decode::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
		let mmr_leaf_hash = Keccak256::hash(&mmr_leaf[..]);
		let mmr_leaf: MmrLeaf =
			Decode::decode(&mut &*mmr_leaf).map_err(|_| Error::CantDecodeMmrLeaf)?;
		// verify mmr_leaf used by mmr_root and mmr_hash
		let result = mmr::verify_leaf_proof(mmr_root, mmr_leaf_hash, mmr_proof)?;
		if !result {
			return Err(Error::InvalidMmrLeafProof)
		}

		Ok((mmr_leaf, signed_commitment))
	}

	fn verify_mmr_lef_with_verify_commitment_and_signature(
		&self,
		signed_commitment: &[u8],
		validator_proofs: &[ValidatorMerkleProof],
		mmr_leaf: &[u8],
		mmr_proof: &[u8],
	) -> Result<(MmrLeaf, SignedCommitment), Error> {
		let (mmr_leaf, signed_commitment) =
			self.verify_mmr_leaf(signed_commitment, mmr_leaf, mmr_proof)?;
		let SignedCommitment { commitment, signatures } = signed_commitment.clone();
		let commitment_hash = commitment.hash();
		// verify commitment and signatures
		LightClient::verify_commitment_signatures(
			&commitment_hash,
			&signatures,
			&self.validator_set.root,
			validator_proofs,
			0,
			signatures.len(),
		)?;

		Ok((mmr_leaf, signed_commitment))
	}

	// Import a signed commitment and update the state of light client.
	pub fn update_state(
		&mut self,
		signed_commitment: &[u8],
		validator_proofs: &[ValidatorMerkleProof],
		mmr_leaf: &[u8],
		mmr_proof: &[u8],
	) -> Result<(), Error> {
		let (mmr_leaf, signed_commitment) = self
			.verify_mmr_lef_with_verify_commitment_and_signature(
				signed_commitment,
				validator_proofs,
				mmr_leaf,
				mmr_proof,
			)?;

		// update the latest commitment, including mmr_root
		self.latest_commitment = Some(signed_commitment.commitment);

		// update validator_set
		if mmr_leaf.beefy_next_authority_set.id > self.validator_set.id {
			self.validator_set = mmr_leaf.beefy_next_authority_set;
		}

		Ok(())
	}

	// Import a signed commitment and verify signatures in multiple steps.
	pub fn start_updating_state(
		&mut self,
		versioned_finality_proof: &[u8],
		validator_proofs: &[ValidatorMerkleProof],
		mmr_leaf: &[u8],
		mmr_proof: &[u8],
	) -> Result<(), Error> {
		let (mmr_leaf, signed_commitment) =
			self.verify_mmr_leaf(versioned_finality_proof, mmr_leaf, mmr_proof)?;

		let commitment_hash = signed_commitment.commitment.hash();

		self.in_process_state = Some(InProcessState {
			position: 0,
			commitment_hash,
			signed_commitment,
			validator_proofs: validator_proofs.to_vec(),
			validator_set: mmr_leaf.beefy_next_authority_set,
		});

		Ok(())
	}

	pub fn complete_updating_state(&mut self, iterations: usize) -> Result<bool, Error> {
		let in_process_state =
			self.in_process_state.as_mut().ok_or(Error::MissingInProcessState)?;
		if in_process_state.position >= in_process_state.signed_commitment.signatures.len() {
			// discard the state
			self.in_process_state = None;
			return Ok(true)
		}
		let iterations = if in_process_state.position + iterations >
			in_process_state.signed_commitment.signatures.len()
		{
			in_process_state.signed_commitment.signatures.len() - in_process_state.position
		} else {
			iterations
		};
		let result = LightClient::verify_commitment_signatures(
			&in_process_state.commitment_hash,
			&in_process_state.signed_commitment.signatures,
			&self.validator_set.root,
			&in_process_state.validator_proofs,
			in_process_state.position,
			iterations,
		);
		match result {
			Ok(_) => {
				in_process_state.position += iterations;
				if in_process_state.position >= in_process_state.signed_commitment.signatures.len()
				{
					// update the latest commitment, including mmr_root
					self.latest_commitment =
						Some(in_process_state.signed_commitment.commitment.clone());

					// update validator_set
					if in_process_state.validator_set.id > self.validator_set.id {
						self.validator_set = in_process_state.validator_set.clone();
					}
					// discard the state
					self.in_process_state = None;

					Ok(true)
				} else {
					Ok(false)
				}
			},
			Err(_) => {
				// discard the state
				self.in_process_state = None;

				Err(Error::InvalidSignature)
			},
		}
	}

	pub fn verify_solochain_messages(
		&self,
		messages: &[u8],
		header: &[u8],
		mmr_leaf: &[u8],
		mmr_proof: &[u8],
	) -> Result<(), Error> {
		let header = Header::decode(&mut &header[..]).map_err(|_| Error::CantDecodeHeader)?;
		let header_digest = header.get_other().ok_or(Error::DigestNotFound)?;

		let messages_hash = Keccak256::hash(messages);
		if messages_hash != header_digest[..] {
			return Err(Error::DigestNotMatch)
		}

		let mmr_root: [u8; 32] = self
			.latest_commitment
			.as_ref()
			.ok_or(Error::MissingLatestCommitment)?
			.payload
			.get_decoded(&MMR_ROOT_ID)
			.ok_or(Error::InvalidCommitmentPayload)?;
		let mmr_proof = mmr::MmrLeafProof::decode(&mut &mmr_proof[..])
			.map_err(|_| Error::CantDecodeMmrProof)?;
		let mmr_leaf: Vec<u8> =
			Decode::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
		let mmr_leaf_hash = Keccak256::hash(&mmr_leaf[..]);
		let mmr_leaf: MmrLeaf =
			Decode::decode(&mut &*mmr_leaf).map_err(|_| Error::CantDecodeMmrLeaf)?;

		let header_hash = header.hash();
		if header_hash != mmr_leaf.parent_number_and_hash.1 {
			return Err(Error::HeaderHashNotMatch)
		}

		let result = mmr::verify_leaf_proof(mmr_root, mmr_leaf_hash, mmr_proof)?;
		if !result {
			return Err(Error::InvalidMmrLeafProof)
		}
		Ok(())
	}

	pub fn verify_parachain_messages(&self) -> Result<(), Error> {
		Ok(())
	}

	fn verify_commitment_signatures(
		commitment_hash: &Hash,
		signatures: &[Option<Signature>],
		validator_set_root: &Hash,
		validator_proofs: &[ValidatorMerkleProof],
		start_position: usize,
		interations: usize,
	) -> Result<(), Error> {
		let msg = libsecp256k1::Message::parse_slice(&commitment_hash[..])
			.or(Err(Error::InvalidMessage))?;
		for signature in signatures.iter().skip(start_position).take(interations).flatten() {
			let sig = libsecp256k1::Signature::parse_standard_slice(&signature.0[..64])
				.or(Err(Error::InvalidSignature))?;
			let recovery_id = libsecp256k1::RecoveryId::parse(signature.0[64])
				.or(Err(Error::InvalidRecoveryId))?;
			let validator = libsecp256k1::recover(&msg, &sig, &recovery_id)
				.or(Err(Error::WrongSignature))?
				.serialize()
				.to_vec();
			let validator_address = Keccak256::hash(&validator[1..])[12..].to_vec();
			let mut found = false;
			for proof in validator_proofs.iter() {
				if validator_address == *proof.leaf {
					found = true;
					if !verify_proof::<Keccak256, _, _>(
						validator_set_root,
						proof.proof.clone(),
						proof.number_of_leaves,
						proof.leaf_index,
						&proof.leaf,
					) {
						return Err(Error::InvalidValidatorProof)
					}
					break
				}
			}
			if !found {
				return Err(Error::ValidatorNotFound)
			}
		}

		Ok(())
	}
	//
	pub fn get_latest_commitment(&self) -> Option<Commitment> {
		self.latest_commitment.as_ref().cloned()
	}
	//
	pub fn is_updating_state(&self) -> bool {
		self.in_process_state.is_some()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{commitment::Signature, mmr::MmrLeafProof};
	use hex_literal::hex;

	#[test]
	fn recover_works() {
		let msg = libsecp256k1::Message::parse_slice(&hex!(
			"14f213146a362c397545659ac7795926514696ad49565972d64964040394482c"
		))
		.unwrap();
		let signature = Signature(hex!("3a481c251a7aa94b89e8160aa9073f74cc24570da13ec9f697a9a7c989943bed31b969b50c47675c11994fbdacb82707293976927922ec8c2124490e417af73300").into());
		let sig = libsecp256k1::Signature::parse_standard_slice(&signature.0[..64]).unwrap();
		let public_key = libsecp256k1::recover(
			&msg,
			&sig,
			&libsecp256k1::RecoveryId::parse(signature.0[64]).unwrap(),
		)
		.unwrap();
		assert_eq!(
			public_key.serialize_compressed(),
			hex!("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1")
		);
	}

	#[test]
	fn verify_validator_proofs_works() {
		let proofs = vec![
			MerkleProof {
				root: [
					190, 171, 181, 52, 208, 35, 61, 63, 243, 167, 41, 72, 146, 79, 19, 208, 223,
					177, 46, 195, 87, 235, 1, 167, 227, 185, 178, 150, 73, 165, 92, 75,
				],
				proof: vec![
					hex!("2434439b3f6496cdfc9295f52379b6dd06c6d3f72bb3fd7f367acf4cde15a5c4").into(),
					hex!("b3a227b15b5de9a1993764d0f15f3f7022dc125b513dcaea84f162dbc8e0cdf1").into(),
					hex!("3839dfbc4125baf6f733c367f7b3ad28627563275b77869297bbfde6374221a9").into(),
				],
				number_of_leaves: 5,
				leaf_index: 0,
				leaf: libsecp256k1::PublicKey::parse_slice(
					&hex!("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1"),
					None,
				)
				.unwrap()
				.serialize_compressed(),
			},
			MerkleProof {
				root: [
					190, 171, 181, 52, 208, 35, 61, 63, 243, 167, 41, 72, 146, 79, 19, 208, 223,
					177, 46, 195, 87, 235, 1, 167, 227, 185, 178, 150, 73, 165, 92, 75,
				],
				proof: vec![
					hex!("ea5e28e6e07cc0d6ea6978c5c161f0da9f05ad6d5c259bd98a38d5ed63c6d66d").into(),
					hex!("b3a227b15b5de9a1993764d0f15f3f7022dc125b513dcaea84f162dbc8e0cdf1").into(),
					hex!("3839dfbc4125baf6f733c367f7b3ad28627563275b77869297bbfde6374221a9").into(),
				],
				number_of_leaves: 5,
				leaf_index: 1,
				leaf: libsecp256k1::PublicKey::parse_slice(
					&hex!("0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27"),
					None,
				)
				.unwrap()
				.serialize_compressed(),
			},
			MerkleProof {
				root: [
					190, 171, 181, 52, 208, 35, 61, 63, 243, 167, 41, 72, 146, 79, 19, 208, 223,
					177, 46, 195, 87, 235, 1, 167, 227, 185, 178, 150, 73, 165, 92, 75,
				],
				proof: vec![
					hex!("54e7776947cbea688edb0eafffef41c9bf1d91bf02b51b0debb8e9234679200a").into(),
					hex!("b15eb71c4432af5175d67d9b32a37c44d7cae4625f4a188ec00fe1dc422c21b7").into(),
					hex!("3839dfbc4125baf6f733c367f7b3ad28627563275b77869297bbfde6374221a9").into(),
				],
				number_of_leaves: 5,
				leaf_index: 2,
				leaf: libsecp256k1::PublicKey::parse_slice(
					&hex!("0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb"),
					None,
				)
				.unwrap()
				.serialize_compressed(),
			},
			MerkleProof {
				root: [
					190, 171, 181, 52, 208, 35, 61, 63, 243, 167, 41, 72, 146, 79, 19, 208, 223,
					177, 46, 195, 87, 235, 1, 167, 227, 185, 178, 150, 73, 165, 92, 75,
				],
				proof: vec![
					hex!("69ccb87a5d16f07350e6181de08bf71dc70c3289ebe67751b7eda1f0b2da965c").into(),
					hex!("b15eb71c4432af5175d67d9b32a37c44d7cae4625f4a188ec00fe1dc422c21b7").into(),
					hex!("3839dfbc4125baf6f733c367f7b3ad28627563275b77869297bbfde6374221a9").into(),
				],
				number_of_leaves: 5,
				leaf_index: 3,
				leaf: libsecp256k1::PublicKey::parse_slice(
					&hex!("03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c"),
					None,
				)
				.unwrap()
				.serialize_compressed(),
			},
			MerkleProof {
				root: [
					190, 171, 181, 52, 208, 35, 61, 63, 243, 167, 41, 72, 146, 79, 19, 208, 223,
					177, 46, 195, 87, 235, 1, 167, 227, 185, 178, 150, 73, 165, 92, 75,
				],
				proof: vec![hex!(
					"a33c1baaa379963ee43c3a7983a3157080c32a462a9774f1fe6d2f0480428e5c"
				)
				.into()],
				number_of_leaves: 5,
				leaf_index: 4,
				leaf: libsecp256k1::PublicKey::parse_slice(
					&hex!("031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa"),
					None,
				)
				.unwrap()
				.serialize_compressed(),
			},
		];

		for proof in proofs {
			assert!(verify_proof::<Keccak256, _, _>(
				&proof.root,
				proof.proof,
				proof.number_of_leaves,
				proof.leaf_index,
				&proof.leaf,
			));
		}
	}

	#[test]
	fn verify_leaf_proof_works() {
		let root_hash = hex!("aa0b510cee4270257f6362a353262253de422f069826b5af4398377a4eee03f7");
		let leaf = hex!("c5010058000000e5ac4bf69913974aeb79779c77d6e22d40575a63d4bca9044b501b12916a6090010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");
		let leaf: Vec<u8> = Decode::decode(&mut &leaf[..]).unwrap();
		let mmr_leaf_hash = Keccak256::hash(&leaf[..]);
		let proof = hex!("580000000000000059000000000000000c638bedc14bfdb5cfb8eb7313f311859820948868afbaa340de2a467f4eec130cd789e49d14c7068ec08e0b5680c5e01b372d28802acaeba7b63a5e1482d5147c0e395b48e5a134164c4dac0b30fc8bfd56756329824e6c70c7325769c92c1ff8");
		let mmr_proof = MmrLeafProof::decode(&mut &proof[..]).unwrap();
		assert_eq!(mmr::verify_leaf_proof(root_hash, mmr_leaf_hash, mmr_proof), Ok(true));
	}
}
