#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::convert::TryInto;
#[cfg(not(feature = "std"))]
use core::result;

#[cfg(feature = "std")]
use std::convert::TryInto;

use beefy_merkle_tree::{merkle_root, verify_proof, Hash, Keccak256, MerkleProof};
use borsh::{BorshDeserialize, BorshSerialize};
use codec::Decode;
use commitment::{Commitment, SignedCommitment};
use header::Header;
use mmr::MmrLeaf;
use validator_set::{BeefyNextAuthoritySet, Public, ValidatorSetId};

pub mod commitment;
pub mod header;
pub mod mmr;
pub mod simplified_mmr;
pub mod validator_set;

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
	InvalidSignedCommitment,
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
}

#[derive(Debug, Default, BorshDeserialize, BorshSerialize)]
pub struct LightClient {
	latest_commitment: Option<Commitment>,
	validator_set: BeefyNextAuthoritySet,
}

// Initialize light client using the BeefyId of the initial validator set.
pub fn new(initial_public_keys: Vec<String>) -> LightClient {
	let initial_public_keys: Vec<Public> = initial_public_keys
		.into_iter()
		.map(|hex_str| {
			hex::decode(&hex_str[2..]).map_or([0; 33], |s| s.try_into().unwrap_or([0; 33]))
		})
		.collect();
	LightClient {
		latest_commitment: None,
		validator_set: BeefyNextAuthoritySet {
			id: 0,
			len: initial_public_keys.len() as u32,
			root: merkle_root::<Keccak256, _, _>(initial_public_keys),
		},
	}
}

impl LightClient {
	// Import a signed commitment and update the state of light client.
	pub fn update_state(
		&mut self,
		signed_commitment: &[u8],
		validator_proofs: Vec<MerkleProof<&Public>>,
		mmr_leaf: &[u8],
		mmr_proof: &[u8],
	) -> Result<(), Error> {
		let signed_commitment = SignedCommitment::decode(&mut &signed_commitment[..])
			.map_err(|_| Error::InvalidSignedCommitment)?;

		if let Some(latest_commitment) = &self.latest_commitment {
			if signed_commitment.commitment <= *latest_commitment {
				return Err(Error::CommitmentAlreadyUpdated);
			}
		}

		let mmr_leaf = MmrLeaf::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
		let mmr_proof = mmr::MmrLeafProof::decode(&mut &mmr_proof[..])
			.map_err(|_| Error::CantDecodeMmrProof)?;

		let commitment = self.verify_commitment(signed_commitment, validator_proofs)?;
		// update the latest commitment, including mmr_root
		self.latest_commitment = Some(commitment);

		let result = self.verify_mmr_leaf(commitment.payload, mmr_leaf.clone(), mmr_proof)?;
		if !result {
			return Err(Error::InvalidMmrLeafProof);
		}

		// update validator_set
		if mmr_leaf.beefy_next_authority_set.id > self.validator_set.id {
			self.validator_set = mmr_leaf.beefy_next_authority_set;
		}
		Ok(())
	}

	pub fn verify_solochain_messages(
		&self,
		messages: &[u8],
		header: &[u8],
		mmr_leaf: &[u8],
		mmr_proof: &[u8],
	) -> Result<(), Error> {
		let mmr_root = self.latest_commitment.ok_or(Error::MissingLatestCommitment)?.payload;
		let header = Header::decode(&mut &header[..]).map_err(|_| Error::CantDecodeHeader)?;
		let mmr_leaf = MmrLeaf::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
		let mmr_proof = mmr::MmrLeafProof::decode(&mut &mmr_proof[..])
			.map_err(|_| Error::CantDecodeMmrProof)?;

		let header_digest = header.get_other().ok_or(Error::DigestNotFound)?;

		let messages_hash = Keccak256::hash(messages);
		if messages_hash != &header_digest[..] {
			return Err(Error::DigestNotMatch);
		}

		let header_hash = header.hash();
		if header_hash != mmr_leaf.parent_number_and_hash.1 {
			return Err(Error::HeaderHashNotMatch);
		}

		self.verify_mmr_leaf(mmr_root, mmr_leaf, mmr_proof)?;
		Ok(())
	}

	pub fn verify_parachain_messages(&self) -> Result<(), Error> {
		Ok(())
	}

	fn verify_commitment(
		&self,
		signed_commitment: SignedCommitment,
		validator_proofs: Vec<MerkleProof<&Public>>,
	) -> Result<Commitment, Error> {
		let SignedCommitment { commitment, signatures } = signed_commitment;
		// TODO: check length
		let commitment_hash = commitment.hash();
		let msg = libsecp256k1::Message::parse_slice(&commitment_hash[..])
			.or(Err(Error::InvalidMessage))?;
		for signature in signatures.into_iter() {
			if let Some(signature) = signature {
				let sig = libsecp256k1::Signature::parse_standard_slice(&signature.0[..64])
					.or(Err(Error::InvalidSignature))?;
				let recovery_id = libsecp256k1::RecoveryId::parse(signature.0[64])
					.or(Err(Error::InvalidRecoveryId))?;
				let validator = libsecp256k1::recover(&msg, &sig, &recovery_id)
					.or(Err(Error::WrongSignature))?
					.serialize_compressed();
				let mut found = false;
				for proof in validator_proofs.iter() {
					if validator == *proof.leaf {
						found = true;
						if !verify_proof::<Keccak256, _, _>(
							&self.validator_set.root,
							proof.proof.clone(),
							proof.number_of_leaves,
							proof.leaf_index,
							&proof.leaf,
						) {
							return Err(Error::InvalidValidatorProof);
						}
						break;
					}
				}
				if !found {
					return Err(Error::ValidatorNotFound);
				}
			}
		}

		Ok(commitment)
	}

	fn verify_mmr_leaf(
		&self,
		root: Hash,
		leaf: MmrLeaf,
		// proof: simplified_mmr::MerkleProof,
		proof: mmr::MmrLeafProof,
	) -> Result<bool, Error> {
		let leaf_hash = leaf.hash();
		// let result = simplified_mmr::verify_proof(root, leaf_hash, proof);
		mmr::verify_leaf_proof(root, leaf_hash, proof)
		// if !result {
		// 	return Err(Error::InvalidMmrProof);
		// }
		// Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		commitment::{Signature, SignedCommitment},
		mmr::MmrLeafProof,
	};
	use hex_literal::hex;

	#[test]
	fn it_works() {
		// $ subkey inspect --scheme ecdsa //Alice
		// Secret Key URI `//Alice` is account:
		//   Public key (hex):  0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
		let public_keys = vec![
			"0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1".to_string(), // Alice
			"0x0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27".to_string(), // Bob
			"0x0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb".to_string(), // Charlie
			"0x03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c".to_string(), // Dave
			"0x031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa".to_string(), // Eve
		];
		let mut lc = new(public_keys);
		println!("light client: {:?}", lc);
		let encoded_signed_commitment_1 = vec![
			128, 63, 134, 61, 200, 97, 32, 23, 104, 25, 243, 188, 168, 45, 250, 252, 113, 40, 48,
			105, 236, 113, 35, 60, 163, 1, 38, 111, 65, 205, 236, 209, 9, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 20, 1, 91, 157, 95, 64, 74, 202, 233, 130, 174, 60, 145, 10, 39, 45, 156, 143,
			103, 180, 246, 96, 207, 133, 159, 64, 176, 80, 82, 179, 118, 121, 221, 26, 96, 71, 218,
			96, 235, 19, 14, 131, 178, 178, 204, 191, 113, 247, 234, 78, 235, 70, 178, 142, 48,
			231, 155, 219, 77, 237, 200, 114, 67, 191, 25, 241, 0, 1, 188, 208, 147, 96, 15, 212,
			183, 34, 189, 17, 14, 16, 109, 116, 170, 229, 181, 146, 9, 232, 188, 245, 28, 107, 164,
			98, 205, 142, 171, 165, 215, 187, 23, 60, 106, 143, 176, 248, 93, 72, 244, 171, 158,
			147, 171, 229, 148, 69, 96, 6, 27, 211, 74, 138, 176, 91, 132, 210, 202, 228, 139, 233,
			103, 185, 0, 1, 229, 11, 119, 228, 142, 191, 100, 187, 79, 202, 195, 58, 137, 7, 177,
			175, 218, 243, 3, 91, 120, 65, 198, 48, 85, 103, 218, 96, 150, 135, 173, 241, 63, 82,
			87, 247, 192, 141, 93, 212, 247, 26, 133, 65, 211, 20, 198, 163, 154, 157, 144, 180,
			109, 15, 139, 238, 165, 21, 225, 119, 165, 39, 210, 90, 0, 0, 1, 178, 62, 203, 100, 96,
			229, 253, 237, 31, 175, 62, 194, 176, 1, 25, 15, 191, 141, 44, 18, 222, 40, 107, 100,
			171, 45, 224, 141, 152, 83, 189, 129, 72, 34, 211, 37, 143, 42, 29, 62, 228, 77, 53,
			181, 97, 25, 228, 125, 30, 164, 50, 196, 86, 46, 254, 14, 155, 254, 3, 187, 84, 144,
			249, 195, 0,
		];

		let signed_commitment_1 = SignedCommitment::decode(&mut &encoded_signed_commitment_1[..]);
		println!("signed_commitment_1: {:?}", signed_commitment_1);
		let alice_pk = libsecp256k1::PublicKey::parse_slice(
			&hex!("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1"),
			None,
		)
		.unwrap()
		.serialize_compressed();
		let bob_pk = libsecp256k1::PublicKey::parse_slice(
			&hex!("0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27"),
			None,
		)
		.unwrap()
		.serialize_compressed();
		let charlie_pk = libsecp256k1::PublicKey::parse_slice(
			&hex!("0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb"),
			None,
		)
		.unwrap()
		.serialize_compressed();
		let dave_pk = libsecp256k1::PublicKey::parse_slice(
			&hex!("03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c"),
			None,
		)
		.unwrap()
		.serialize_compressed();
		let eve_pk = libsecp256k1::PublicKey::parse_slice(
			&hex!("031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa"),
			None,
		)
		.unwrap()
		.serialize_compressed();

		let proofs_1 = vec![
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
				leaf: &alice_pk,
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
				leaf: &bob_pk,
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
				leaf: &charlie_pk,
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
				leaf: &dave_pk,
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
				leaf: &eve_pk,
			},
		];
		println!("proofs_1: {:?}", proofs_1);

		let encoded_mmr_leaf_1 = vec![
			197, 1, 0, 80, 2, 0, 0, 215, 232, 64, 39, 138, 137, 92, 111, 203, 89, 109, 35, 222,
			184, 160, 96, 110, 238, 222, 180, 124, 34, 185, 255, 101, 17, 42, 4, 21, 13, 10, 64, 1,
			0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 48, 72, 3, 250, 90, 145, 217, 133, 44, 170, 254, 4,
			180, 184, 103, 164, 237, 39, 160, 122, 91, 238, 61, 21, 7, 180, 177, 135, 166, 135,
			119, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0,
		];

		let mmr_leaf_1 = MmrLeaf::decode(&mut &encoded_mmr_leaf_1[..]);
		println!("mmr_leaf_1: {:?}", mmr_leaf_1);

		let encoded_mmr_proof_1 = vec![
			80, 2, 0, 0, 0, 0, 0, 0, 81, 2, 0, 0, 0, 0, 0, 0, 12, 170, 169, 214, 170, 221, 156, 76,
			239, 118, 2, 95, 188, 66, 102, 27, 216, 239, 33, 139, 135, 245, 88, 81, 154, 85, 165,
			111, 189, 30, 248, 144, 132, 55, 211, 139, 171, 189, 76, 229, 184, 51, 53, 116, 76, 97,
			218, 194, 250, 245, 186, 35, 233, 34, 116, 206, 131, 244, 206, 56, 141, 118, 64, 200,
			249, 233, 120, 75, 100, 195, 5, 187, 143, 112, 31, 118, 190, 209, 5, 206, 115, 63, 161,
			237, 82, 9, 226, 139, 116, 28, 176, 86, 151, 47, 247, 58, 127,
		];
		let mmr_proof_1 = MmrLeafProof::decode(&mut &encoded_mmr_proof_1[..]);
		println!("mmr_proof_1: {:?}", mmr_proof_1);
		assert!(lc
			.update_state(
				&encoded_signed_commitment_1,
				proofs_1,
				&encoded_mmr_leaf_1,
				&encoded_mmr_proof_1,
			)
			.is_ok());
		println!("light client: {:?}", lc);
	}

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
}
