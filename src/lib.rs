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

		let mmr_leaf_hash = Keccak256::hash(&mmr_leaf[..]);
		let mmr_leaf: Vec<u8> =
			Decode::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
		let mmr_leaf: MmrLeaf =
			Decode::decode(&mut &*mmr_leaf).map_err(|_| Error::CantDecodeMmrLeaf)?;

		let mmr_proof = mmr::MmrLeafProof::decode(&mut &mmr_proof[..])
			.map_err(|_| Error::CantDecodeMmrProof)?;

		let commitment = self.verify_commitment(signed_commitment, validator_proofs)?;
		if cfg!(feature = "std") {
			println!("commitment {:?}", commitment);
		}
		// update the latest commitment, including mmr_root
		self.latest_commitment = Some(commitment);

		let result = self.verify_mmr_leaf(commitment.payload, mmr_leaf_hash, mmr_proof)?;
		if cfg!(feature = "std") {
			println!("verify_mmr_leaf {:?}", result);
		}
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
		let mmr_leaf_hash = Keccak256::hash(&mmr_leaf[..]);
		let mmr_leaf: Vec<u8> =
			Decode::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
		let mmr_leaf: MmrLeaf =
			Decode::decode(&mut &*mmr_leaf).map_err(|_| Error::CantDecodeMmrLeaf)?;
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

		self.verify_mmr_leaf(mmr_root, mmr_leaf_hash, mmr_proof)?;
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
		root_hash: Hash,
		leaf_hash: Hash,
		// proof: simplified_mmr::MerkleProof,
		proof: mmr::MmrLeafProof,
	) -> Result<bool, Error> {
		// let leaf_hash = leaf.hash();
		// let result = simplified_mmr::verify_proof(root, leaf_hash, proof);
		mmr::verify_leaf_proof(root_hash, leaf_hash, proof)
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

		let encoded_signed_commitment_1 = hex!("f45927644a0b5bc6f1ce667330071fbaea498403c084eb0d4cb747114887345d0900000000000000000000001401b9b5b39fb15d7e22710ad06075cf0e20c4b0c1e3d0a6482946e1d0daf86ca2e37b40209316f00a549cdd2a7fd191694fee4f76f698d0525642563e665db85d6300010ee39cb2cb008f7dce753541b5442e98a260250286b335d6048f2dd4695237655ccc93ebcd3d7c04461e0b9d12b81b21a826c5ee3eebcd6ab9e85c8717f6b1ae010001b094279e0bb4442ba07165da47ab9c0d7d0f479e31d42c879564915714e8ea3d42393dc430addc4a5f416316c02e0676e525c56a3d0c0033224ebda4c83052670001f965d806a16c5dfb9d119f78cdbed379bccb071528679306208880ad29a9cf9e00e75f1b284fa3457b7b37223a2272cf2bf90ce4fd7e84e321eddec3cdeb66f801");
		let signed_commitment_1 = SignedCommitment::decode(&mut &encoded_signed_commitment_1[..]);
		println!("signed_commitment_1: {:?}", signed_commitment_1);

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

		let  encoded_mmr_leaf_1 = hex!("c501000800000079f0451c096266bee167393545bafc7b27b7d14810084a843955624588ba29c1010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

		let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_1[..]).unwrap();
		let mmr_leaf_1: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
		println!("mmr_leaf_1: {:?}", mmr_leaf_1);

		let encoded_mmr_proof_1 =  hex!("0800000000000000090000000000000004c2d6348aef1ef52e779c59bcc1d87fa0175b59b4fa2ea8fc322e4ceb2bdd1ea2");
		let mmr_proof_1 = MmrLeafProof::decode(&mut &encoded_mmr_proof_1[..]);
		println!("mmr_proof_1: {:?}", mmr_proof_1);
		let result = lc
			.update_state(
				&encoded_signed_commitment_1,
				proofs_1,
				&encoded_mmr_leaf_1,
				&encoded_mmr_proof_1,
			)
			.is_ok();
		println!("light client: {:?} {}", lc, result);

		let encoded_signed_commitment_2 = hex!("8d3cb96dca5110aff60423046bbf4a76db0e71158aa5586ffa3423fbaf9ef1da1100000000000000000000001401864ce4553324cc92db4ac622b9dbb031a6a4bd26ee1ab66e0272f567928865ec46847b55f98fa7e1dbafb0256f0a23e2f0a375e4547f5d1819d9b8694f17f6a80101c9ae8aad1b81e2249736324716c09c122889317e4f3e47066c501a839c15312e5c823dd37436d8e3bac8041329c5d0ed5dd94c45b5c1eed13d9111924f0a13c1000159fe06519c672d183de7776b6902a13c098d917721b5600a2296dca3a74a81bc01031a671fdb5e5050ff1f432d72e7a2c144ab38f8401ffd368e693257162a4600014290c6aa5028ceb3a3a773c80beee2821f3a7f5b43f592f7a82b0cbbbfab5ba41363daae5a7006fea2f89a30b4900f85fa82283587df789fd7b5b773ad7e8c410100");
		let signed_commitment_2 = SignedCommitment::decode(&mut &encoded_signed_commitment_2[..]);
		println!("signed_commitment_2: {:?}", signed_commitment_2);

		let proofs_2 = vec![
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
		println!("proofs_2: {:?}", proofs_2);

		let  encoded_mmr_leaf_2 = hex!("c5010010000000d0a3a930e5f3b0f997c3794023c86f8ba28c6ba2cacf230d08d46be0fdf29435010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

		let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_2[..]).unwrap();
		let mmr_leaf_2: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
		println!("mmr_leaf_2: {:?}", mmr_leaf_2);

		let encoded_mmr_proof_2 =  hex!("10000000000000001100000000000000048a766e1ab001e2ff796517dcfbff957a751c994aff4c3ba9447a46d88ec2ef15");
		let mmr_proof_2 = MmrLeafProof::decode(&mut &encoded_mmr_proof_2[..]);
		println!("mmr_proof_2: {:?}", mmr_proof_2);
		assert!(lc
			.update_state(
				&encoded_signed_commitment_2,
				proofs_2,
				&encoded_mmr_leaf_2,
				&encoded_mmr_proof_2,
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
