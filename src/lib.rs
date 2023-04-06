#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use binary_merkle_tree::{merkle_root, verify_proof};
use borsh::{BorshDeserialize, BorshSerialize};
use codec::{Decode, Encode};
use commitment::{
	known_payload_ids::MMR_ROOT_ID, Commitment, Signature, SignedCommitment, VersionedFinalityProof,
};
use hash_db::Hasher;
use header::Header;
use validator_set::BeefyNextAuthoritySet;

pub use binary_merkle_tree::MerkleProof;

pub mod commitment;
pub mod errors;
pub mod header;
pub mod keccak256;
pub mod mmr;
pub mod simplified_mmr;
pub mod validator_set;

use crate::keccak256::Keccak256;
pub use commitment::BeefyPayloadId;
use errors::Error;

/// Supported hashing output size.
///
/// The size is restricted to 32 bytes to allow for a more optimised implementation.
pub type Hash = [u8; 32];

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

/// ref: https://github.com/paritytech/substrate/blob/9c92e4987160a17daa72f79186d981b6fbe5879e/utils/binary-merkle-tree/src/lib.rs#L92
#[derive(
	Debug, Default, Clone, Encode, Decode, PartialEq, Eq, BorshDeserialize, BorshSerialize,
)]
pub struct ValidatorMerkleProof {
	/// Root hash of generated merkle tree.
	pub root: Hash,
	/// Proof items (does not contain the leaf hash, nor the root obviously).
	///
	/// This vec contains all inner node hashes necessary to reconstruct the root hash given the
	/// leaf hash.
	pub proof: Vec<Hash>,
	/// Number of leaves in the original tree.
	///
	/// This is needed to detect a case where we have an odd number of leaves that "get promoted"
	/// to upper layers.
	pub number_of_leaves: u64,
	/// Index of the leaf the proof is for (0-based).
	pub leaf_index: u64,
	/// Leaf content.
	pub leaf: Vec<u8>,
}

impl From<binary_merkle_tree::MerkleProof<Hash, Vec<u8>>> for ValidatorMerkleProof {
	fn from(value: binary_merkle_tree::MerkleProof<Hash, Vec<u8>>) -> Self {
		Self {
			root: value.root,
			proof: value.proof,
			number_of_leaves: value.number_of_leaves as u64,
			leaf_index: value.leaf_index as u64,
			leaf: value.leaf,
		}
	}
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct InProcessState {
	pub position: usize,
	commitment_hash: Hash,
	signed_commitment: SignedCommitment,
	validator_set_proof: Vec<ValidatorMerkleProof>,
	validator_set: BeefyNextAuthoritySet<Hash>,
}

#[derive(Debug, Default, BorshDeserialize, BorshSerialize)]
pub struct LightClient {
	pub latest_commitment: Option<Commitment>,
	pub validator_set: BeefyNextAuthoritySet<Hash>,
	pub in_process_state: Option<InProcessState>,
}

impl LightClient {
	// Initialize light client using the BeefyId of the initial validator set.
	pub fn new(initial_public_keys: Vec<String>) -> LightClient {
		let initial_public_keys = initial_public_keys
			.into_iter()
			.map(|key| if key.starts_with("0x") { key } else { format!("0x{key}") })
			.collect::<Vec<_>>();
		let initial_public_keys: Vec<Vec<u8>> = initial_public_keys
			.into_iter()
			.map(|hex_str| {
				hex::decode(&hex_str[2..])
					.map(|compressed_key| beefy_ecdsa_to_ethereum(&compressed_key))
					.unwrap_or_default()
			})
			.collect();

		LightClient {
			latest_commitment: None,
			validator_set: BeefyNextAuthoritySet {
				id: 0,
				len: initial_public_keys.len() as u32,
				root: merkle_root::<Keccak256, _>(initial_public_keys),
			},
			in_process_state: None,
		}
	}

	fn decode_versioned_finality_proof(
		versioned_finality_proof: &[u8],
	) -> Result<VersionedFinalityProof, Error> {
		VersionedFinalityProof::decode(&mut &versioned_finality_proof[..])
			.map_err(|_| Error::InvalidVersionedFinalityProof)
	}

	fn decode_authority_set_proof(
		authority_set_proof: &[Vec<u8>],
	) -> Result<Vec<ValidatorMerkleProof>, Error> {
		authority_set_proof
			.iter()
			.map(|data| {
				ValidatorMerkleProof::decode(&mut &data[..])
					.map_err(|_| Error::InvalidValidatorProof)
			})
			.collect::<Result<Vec<ValidatorMerkleProof>, Error>>()
	}

	fn decode_mmr_leaves_and_proof(
		mmr_leaves: &[u8],
		mmr_proof: &[u8],
	) -> Result<(Vec<Hash>, mmr::MmrLeavesProof), Error> {
		let mmr_proof = mmr::MmrLeavesProof::try_from(mmr_proof.to_vec())?;

		let opaque_mmr_leaves: Vec<mmr::EncodableOpaqueLeaf> = Decode::decode(&mut &mmr_leaves[..])
			.map_err(|_| Error::Other("decode EncodableOpaqueLeaf vector failed".to_string()))?;
		let hash_leaves = opaque_mmr_leaves
			.into_iter()
			.map(|leaf| Keccak256::hash(&leaf.0))
			.collect::<Vec<Hash>>();

		Ok((hash_leaves, mmr_proof))
	}

	fn max_mmr_leaf_by_authority_set_id(mmr_leaves: &[u8]) -> Result<mmr::MmrLeaf, Error> {
		mmr::decode_mmr_leaves(mmr_leaves.to_vec())?
			.into_iter()
			.max_by(|x, y| x.beefy_next_authority_set.id.cmp(&y.beefy_next_authority_set.id))
			.ok_or(Error::Other("cannt find max mmr leaf".to_string()))
	}
}

impl LightClient {
	// Import a signed commitment and update the state of light client.
	pub fn update_state(
		&mut self,
		versioned_finality_proof: &[u8],
		authority_set_proof: &[Vec<u8>],
		mmr_leaves: Option<&[u8]>,
		mmr_proof: Option<&[u8]>,
	) -> Result<(), Error> {
		let VersionedFinalityProof::V1(signed_commitment) =
			LightClient::decode_versioned_finality_proof(versioned_finality_proof)?;

		if let Some(latest_commitment) = &self.latest_commitment {
			if signed_commitment.commitment <= *latest_commitment {
				return Err(Error::CommitmentAlreadyUpdated)
			}
		}

		let signatures_count =
			signed_commitment.signatures.iter().filter(|&sig| sig.is_some()).count();
		if signatures_count < (self.validator_set.len / 2) as usize {
			return Err(Error::InvalidNumberOfSignatures {
				expected: (self.validator_set.len / 2) as usize,
				got: signatures_count,
			})
		}

		let SignedCommitment { commitment, signatures } = signed_commitment;
		let commitment_hash = commitment.hash();

		let validator_set_proof = LightClient::decode_authority_set_proof(authority_set_proof)?;

		LightClient::verify_commitment_signatures(
			&commitment_hash,
			&signatures,
			&self.validator_set.root,
			&validator_set_proof,
			0,
			signatures.len(),
		)?;

		let mmr_root: [u8; 32] = commitment
			.payload
			.get_decoded(&MMR_ROOT_ID)
			.ok_or(Error::InvalidCommitmentPayload)?;

		if let (Some(mmr_leaves), Some(mmr_proof)) = (mmr_leaves, mmr_proof) {
			let (hash_leaves, mmr_proof) =
				LightClient::decode_mmr_leaves_and_proof(mmr_leaves, mmr_proof)?;

			let result = mmr::verify_leaf_proof(mmr_root, hash_leaves, mmr_proof)?;
			if !result {
				return Err(Error::InvalidMmrLeafProof)
			}

			// update the latest commitment, including mmr_root
			self.latest_commitment = Some(commitment);

			// get max mmr leaf by authority set id
			let max_mmr_leaf_by_authority_set_id =
				LightClient::max_mmr_leaf_by_authority_set_id(mmr_leaves)?;

			// update validator_set
			if max_mmr_leaf_by_authority_set_id.beefy_next_authority_set.id > self.validator_set.id
			{
				self.validator_set = max_mmr_leaf_by_authority_set_id.beefy_next_authority_set;
			}
		}

		Ok(())
	}

	// Import a signed commitment and verify signatures in multiple steps.
	pub fn start_updating_state(
		&mut self,
		versioned_finality_proof: &[u8],
		authority_set_proof: &[Vec<u8>],
		mmr_leaves: &[u8],
		mmr_proof: &[u8],
	) -> Result<(), Error> {
		let VersionedFinalityProof::V1(signed_commitment) =
			LightClient::decode_versioned_finality_proof(versioned_finality_proof)?;

		if let Some(latest_commitment) = &self.latest_commitment {
			if signed_commitment.commitment <= *latest_commitment {
				return Err(Error::CommitmentAlreadyUpdated)
			}
		}

		let signatures_count =
			signed_commitment.signatures.iter().filter(|&sig| sig.is_some()).count();
		if signatures_count < (self.validator_set.len / 2) as usize {
			return Err(Error::InvalidNumberOfSignatures {
				expected: (self.validator_set.len / 2) as usize,
				got: signatures_count,
			})
		}

		let mmr_root: [u8; 32] = signed_commitment
			.commitment
			.payload
			.get_decoded(&MMR_ROOT_ID)
			.ok_or(Error::InvalidCommitmentPayload)?;

		let (hash_leaves, mmr_proof) =
			LightClient::decode_mmr_leaves_and_proof(mmr_leaves, mmr_proof)?;

		let result = mmr::verify_leaf_proof(mmr_root, hash_leaves, mmr_proof)?;
		if !result {
			return Err(Error::InvalidMmrLeafProof)
		}

		let commitment_hash = signed_commitment.commitment.hash();

		let validator_set_proof = LightClient::decode_authority_set_proof(authority_set_proof)?;

		let max_mmr_leaf_by_authority_set_id =
			LightClient::max_mmr_leaf_by_authority_set_id(mmr_leaves)?;

		self.in_process_state = Some(InProcessState {
			position: 0,
			commitment_hash,
			signed_commitment,
			validator_set_proof: validator_set_proof.to_vec(),
			validator_set: max_mmr_leaf_by_authority_set_id.beefy_next_authority_set,
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
			&in_process_state.validator_set_proof,
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
		mmr_leaves: &[u8],
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

		let max_mmr_leaf_by_authority_set_id =
			LightClient::max_mmr_leaf_by_authority_set_id(mmr_leaves)?;

		let header_hash = header.hash();
		// todo by davirian maybe have error
		if header_hash != max_mmr_leaf_by_authority_set_id.parent_number_and_hash.1 {
			return Err(Error::HeaderHashNotMatch)
		}

		let (hash_leaves, mmr_proof) =
			LightClient::decode_mmr_leaves_and_proof(mmr_leaves, mmr_proof)?;

		let result = mmr::verify_leaf_proof(mmr_root, hash_leaves, mmr_proof)?;
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
		validator_set_proof: &[ValidatorMerkleProof],
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
			for proof in validator_set_proof.iter() {
				if validator_address == *proof.leaf {
					found = true;
					if !verify_proof::<Keccak256, _, _>(
						validator_set_root,
						proof.proof.clone(),
						proof.number_of_leaves as usize,
						proof.leaf_index as usize,
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
	use crate::commitment::Signature;
	use binary_merkle_tree::merkle_proof;
	use hex_literal::hex;

	#[test]
	fn recover_works() {
		let msg = libsecp256k1::Message::parse_slice(&hex!(
			"14f213146a362c397545659ac7795926514696ad49565972d64964040394482c"
		))
		.unwrap();
		let signature = Signature(hex!("3a481c251a7aa94b89e8160aa9073f74cc24570da13ec9f697a9a7c989943bed31b969b50c47675c11994fbdacb82707293976927922ec8c2124490e417af73300"));
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
	fn verify_validator_set_proof_works() {
		let public_keys = vec![
			"020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1", // Alice
			"0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27", // Bob
			"0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb", // Charlie
			"03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c", // Dave
			"031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa", // Eve
		];

		let leaves = public_keys
			.into_iter()
			.map(|leaf| beefy_ecdsa_to_ethereum(&hex::decode(leaf).unwrap()))
			.collect::<Vec<_>>();

		let validator_merkle_proof = (0..5usize).fold(vec![], |mut result, idx| {
			let merkle_proof: binary_merkle_tree::MerkleProof<Hash, Vec<u8>> =
				binary_merkle_tree::merkle_proof::<Keccak256, _, _>(leaves.clone(), idx);
			result.push(merkle_proof);
			result
		});

		for proof in validator_merkle_proof {
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
	fn should_generate_and_verify_proof_large() {
		let mut data = vec![];
		for i in 1..16 {
			for c in 'a'..='z' {
				if c as usize % i != 0 {
					data.push(c.to_string());
				}
			}

			for l in 0..data.len() {
				// when
				let proof = merkle_proof::<Keccak256, _, _>(data.clone(), l);
				// then
				assert!(verify_proof::<Keccak256, _, _>(
					&proof.root,
					proof.proof,
					data.len(),
					proof.leaf_index,
					&proof.leaf
				));
			}
		}
	}

	#[test]
	fn should_generate_and_verify_proof_on_test_data() {
		let addresses = vec![
			"0x9aF1Ca5941148eB6A3e9b9C741b69738292C533f",
			"0xDD6ca953fddA25c496165D9040F7F77f75B75002",
			"0x60e9C47B64Bc1C7C906E891255EaEC19123E7F42",
			"0xfa4859480Aa6D899858DE54334d2911E01C070df",
			"0x19B9b128470584F7209eEf65B69F3624549Abe6d",
			"0xC436aC1f261802C4494504A11fc2926C726cB83b",
			"0xc304C8C2c12522F78aD1E28dD86b9947D7744bd0",
			"0xDa0C2Cba6e832E55dE89cF4033affc90CC147352",
			"0xf850Fd22c96e3501Aad4CDCBf38E4AEC95622411",
			"0x684918D4387CEb5E7eda969042f036E226E50642",
			"0x963F0A1bFbb6813C0AC88FcDe6ceB96EA634A595",
			"0x39B38ad74b8bCc5CE564f7a27Ac19037A95B6099",
			"0xC2Dec7Fdd1fef3ee95aD88EC8F3Cd5bd4065f3C7",
			"0x9E311f05c2b6A43C2CCF16fB2209491BaBc2ec01",
			"0x927607C30eCE4Ef274e250d0bf414d4a210b16f0",
			"0x98882bcf85E1E2DFF780D0eB360678C1cf443266",
			"0xFBb50191cd0662049E7C4EE32830a4Cc9B353047",
			"0x963854fc2C358c48C3F9F0A598B9572c581B8DEF",
			"0xF9D7Bc222cF6e3e07bF66711e6f409E51aB75292",
			"0xF2E3fd32D063F8bBAcB9e6Ea8101C2edd899AFe6",
			"0x407a5b9047B76E8668570120A96d580589fd1325",
			"0xEAD9726FAFB900A07dAd24a43AE941d2eFDD6E97",
			"0x42f5C8D9384034A9030313B51125C32a526b6ee8",
			"0x158fD2529Bc4116570Eb7C80CC76FEf33ad5eD95",
			"0x0A436EE2E4dEF3383Cf4546d4278326Ccc82514E",
			"0x34229A215db8FeaC93Caf8B5B255e3c6eA51d855",
			"0xEb3B7CF8B1840242CB98A732BA464a17D00b5dDF",
			"0x2079692bf9ab2d6dc7D79BBDdEE71611E9aA3B72",
			"0x46e2A67e5d450e2Cf7317779f8274a2a630f3C9B",
			"0xA7Ece4A5390DAB18D08201aE18800375caD78aab",
			"0x15E1c0D24D62057Bf082Cb2253dA11Ef0d469570",
			"0xADDEF4C9b5687Eb1F7E55F2251916200A3598878",
			"0xe0B16Fb96F936035db2b5A68EB37D470fED2f013",
			"0x0c9A84993feaa779ae21E39F9793d09e6b69B62D",
			"0x3bc4D5148906F70F0A7D1e2756572655fd8b7B34",
			"0xFf4675C26903D5319795cbd3a44b109E7DDD9fDe",
			"0xCec4450569A8945C6D2Aba0045e4339030128a92",
			"0x85f0584B10950E421A32F471635b424063FD8405",
			"0xb38bEe7Bdc0bC43c096e206EFdFEad63869929E3",
			"0xc9609466274Fef19D0e58E1Ee3b321D5C141067E",
			"0xa08EA868cF75268E7401021E9f945BAe73872ecc",
			"0x67C9Cb1A29E964Fe87Ff669735cf7eb87f6868fE",
			"0x1B6BEF636aFcdd6085cD4455BbcC93796A12F6E2",
			"0x46B37b243E09540b55cF91C333188e7D5FD786dD",
			"0x8E719E272f62Fa97da93CF9C941F5e53AA09e44a",
			"0xa511B7E7DB9cb24AD5c89fBb6032C7a9c2EfA0a5",
			"0x4D11FDcAeD335d839132AD450B02af974A3A66f8",
			"0xB8cf790a5090E709B4619E1F335317114294E17E",
			"0x7f0f57eA064A83210Cafd3a536866ffD2C5eDCB3",
			"0xC03C848A4521356EF800e399D889e9c2A25D1f9E",
			"0xC6b03DF05cb686D933DD31fCa5A993bF823dc4FE",
			"0x58611696b6a8102cf95A32c25612E4cEF32b910F",
			"0x2ed4bC7197AEF13560F6771D930Bf907772DE3CE",
			"0x3C5E58f334306be029B0e47e119b8977B2639eb4",
			"0x288646a1a4FeeC560B349d210263c609aDF649a6",
			"0xb4F4981E0d027Dc2B3c86afA0D0fC03d317e83C0",
			"0xaAE4A87F8058feDA3971f9DEd639Ec9189aA2500",
			"0x355069DA35E598913d8736E5B8340527099960b8",
			"0x3cf5A0F274cd243C0A186d9fCBdADad089821B93",
			"0xca55155dCc4591538A8A0ca322a56EB0E4aD03C4",
			"0xE824D0268366ec5C4F23652b8eD70D552B1F2b8B",
			"0x84C3e9B25AE8a9b39FF5E331F9A597F2DCf27Ca9",
			"0xcA0018e278751De10d26539915d9c7E7503432FE",
			"0xf13077dE6191D6c1509ac7E088b8BE7Fe656c28b",
			"0x7a6bcA1ec9Db506e47ac6FD86D001c2aBc59C531",
			"0xeA7f9A2A9dd6Ba9bc93ca615C3Ddf26973146911",
			"0x8D0d8577e16F8731d4F8712BAbFa97aF4c453458",
			"0xB7a7855629dF104246997e9ACa0E6510df75d0ea",
			"0x5C1009BDC70b0C8Ab2e5a53931672ab448C17c89",
			"0x40B47D1AfefEF5eF41e0789F0285DE7b1C31631C",
			"0x5086933d549cEcEB20652CE00973703CF10Da373",
			"0xeb364f6FE356882F92ae9314fa96116Cf65F47d8",
			"0xdC4D31516A416cEf533C01a92D9a04bbdb85EE67",
			"0x9b36E086E5A274332AFd3D8509e12ca5F6af918d",
			"0xBC26394fF36e1673aE0608ce91A53B9768aD0D76",
			"0x81B5AB400be9e563fA476c100BE898C09966426c",
			"0x9d93C8ae5793054D28278A5DE6d4653EC79e90FE",
			"0x3B8E75804F71e121008991E3177fc942b6c28F50",
			"0xC6Eb5886eB43dD473f5BB4e21e56E08dA464D9B4",
			"0xfdf1277b71A73c813cD0e1a94B800f4B1Db66DBE",
			"0xc2ff2cCc98971556670e287Ff0CC39DA795231ad",
			"0x76b7E1473f0D0A87E9B4a14E2B179266802740f5",
			"0xA7Bc965660a6EF4687CCa4F69A97563163A3C2Ef",
			"0xB9C2b47888B9F8f7D03dC1de83F3F55E738CebD3",
			"0xEd400162E6Dd6bD2271728FFb04176bF770De94a",
			"0xE3E8331156700339142189B6E555DCb2c0962750",
			"0xbf62e342Bc7706a448EdD52AE871d9C4497A53b1",
			"0xb9d7A1A111eed75714a0AcD2dd467E872eE6B03D",
			"0x03942919DFD0383b8c574AB8A701d89fd4bfA69D",
			"0x0Ef4C92355D3c8c7050DFeb319790EFCcBE6fe9e",
			"0xA6895a3cf0C60212a73B3891948ACEcF1753f25E",
			"0x0Ed509239DB59ef3503ded3d31013C983d52803A",
			"0xc4CE8abD123BfAFc4deFf37c7D11DeCd5c350EE4",
			"0x4A4Bf59f7038eDcd8597004f35d7Ee24a7Bdd2d3",
			"0x5769E8e8A2656b5ed6b6e6fa2a2bFAeaf970BB87",
			"0xf9E15cCE181332F4F57386687c1776b66C377060",
			"0xc98f8d4843D56a46C21171900d3eE538Cc74dbb5",
			"0x3605965B47544Ce4302b988788B8195601AE4dEd",
			"0xe993BDfdcAac2e65018efeE0F69A12678031c71d",
			"0x274fDf8801385D3FAc954BCc1446Af45f5a8304c",
			"0xBFb3f476fcD6429F4a475bA23cEFdDdd85c6b964",
			"0x806cD16588Fe812ae740e931f95A289aFb4a4B50",
			"0xa89488CE3bD9C25C3aF797D1bbE6CA689De79d81",
			"0xd412f1AfAcf0Ebf3Cd324593A231Fc74CC488B12",
			"0xd1f715b2D7951d54bc31210BbD41852D9BF98Ed1",
			"0xf65aD707c344171F467b2ADba3d14f312219cE23",
			"0x2971a4b242e9566dEF7bcdB7347f5E484E11919B",
			"0x12b113D6827E07E7D426649fBd605f427da52314",
			"0x1c6CA45171CDb9856A6C9Dba9c5F1216913C1e97",
			"0x11cC6ee1d74963Db23294FCE1E3e0A0555779CeA",
			"0x8Aa1C721255CDC8F895E4E4c782D86726b068667",
			"0xA2cDC1f37510814485129aC6310b22dF04e9Bbf0",
			"0xCf531b71d388EB3f5889F1f78E0d77f6fb109767",
			"0xBe703e3545B2510979A0cb0C440C0Fba55c6dCB5",
			"0x30a35886F989db39c797D8C93880180Fdd71b0c8",
			"0x1071370D981F60c47A9Cd27ac0A61873a372cBB2",
			"0x3515d74A11e0Cb65F0F46cB70ecf91dD1712daaa",
			"0x50500a3c2b7b1229c6884505D00ac6Be29Aecd0C",
			"0x9A223c2a11D4FD3585103B21B161a2B771aDA3d1",
			"0xd7218df03AD0907e6c08E707B15d9BD14285e657",
			"0x76CfD72eF5f93D1a44aD1F80856797fBE060c70a",
			"0x44d093cB745944991EFF5cBa151AA6602d6f5420",
			"0x626516DfF43bf09A71eb6fd1510E124F96ED0Cde",
			"0x6530824632dfe099304E2DC5701cA99E6d031E08",
			"0x57e6c423d6a7607160d6379A0c335025A14DaFC0",
			"0x3966D4AD461Ef150E0B10163C81E79b9029E69c3",
			"0xF608aCfd0C286E23721a3c347b2b65039f6690F1",
			"0xbfB8FAac31A25646681936977837f7740fCd0072",
			"0xd80aa634a623a7ED1F069a1a3A28a173061705c7",
			"0x9122a77B36363e24e12E1E2D73F87b32926D3dF5",
			"0x62562f0d1cD31315bCCf176049B6279B2bfc39C2",
			"0x48aBF7A2a7119e5675059E27a7082ba7F38498b2",
			"0xb4596983AB9A9166b29517acD634415807569e5F",
			"0x52519D16E20BC8f5E96Da6d736963e85b2adA118",
			"0x7663893C3dC0850EfC5391f5E5887eD723e51B83",
			"0x5FF323a29bCC3B5b4B107e177EccEF4272959e61",
			"0xee6e499AdDf4364D75c05D50d9344e9daA5A9AdF",
			"0x1631b0BD31fF904aD67dD58994C6C2051CDe4E75",
			"0xbc208e9723D44B9811C428f6A55722a26204eEF2",
			"0xe76103a222Ee2C7Cf05B580858CEe625C4dc00E1",
			"0xC71Bb2DBC51760f4fc2D46D84464410760971B8a",
			"0xB4C18811e6BFe564D69E12c224FFc57351f7a7ff",
			"0xD11DB0F5b41061A887cB7eE9c8711438844C298A",
			"0xB931269934A3D4432c084bAAc3d0de8143199F4f",
			"0x070037cc85C761946ec43ea2b8A2d5729908A2a1",
			"0x2E34aa8C95Ffdbb37f14dCfBcA69291c55Ba48DE",
			"0x052D93e8d9220787c31d6D83f87eC7dB088E998f",
			"0x498dAC6C69b8b9ad645217050054840f1D91D029",
			"0xE4F7D60f9d84301e1fFFd01385a585F3A11F8E89",
			"0xEa637992f30eA06460732EDCBaCDa89355c2a107",
			"0x4960d8Da07c27CB6Be48a79B96dD70657c57a6bF",
			"0x7e471A003C8C9fdc8789Ded9C3dbe371d8aa0329",
			"0xd24265Cc10eecb9e8d355CCc0dE4b11C556E74D7",
			"0xDE59C8f7557Af779674f41CA2cA855d571018690",
			"0x2fA8A6b3b6226d8efC9d8f6EBDc73Ca33DDcA4d8",
			"0xe44102664c6c2024673Ff07DFe66E187Db77c65f",
			"0x94E3f4f90a5f7CBF2cc2623e66B8583248F01022",
			"0x0383EdBbc21D73DEd039E9C1Ff6bf56017b4CC40",
			"0x64C3E49898B88d1E0f0d02DA23E0c00A2Cd0cA99",
			"0xF4ccfB67b938d82B70bAb20975acFAe402E812E1",
			"0x4f9ee5829e9852E32E7BC154D02c91D8E203e074",
			"0xb006312eF9713463bB33D22De60444Ba95609f6B",
			"0x7Cbe76ef69B52110DDb2e3b441C04dDb11D63248",
			"0x70ADEEa65488F439392B869b1Df7241EF317e221",
			"0x64C0bf8AA36Ba590477585Bc0D2BDa7970769463",
			"0xA4cDc98593CE52d01Fe5Ca47CB3dA5320e0D7592",
			"0xc26B34D375533fFc4c5276282Fa5D660F3d8cbcB",
		];
		let root: [u8; 32] = array_bytes::hex2array_unchecked(
			"7b2c6eebec6e85b2e272325a11c31af71df52bc0534d2d4f903e0ced191f022e",
		);

		let data = addresses.into_iter().map(array_bytes::hex2bytes_unchecked).collect::<Vec<_>>();

		for l in 0..data.len() {
			// when
			let proof = merkle_proof::<Keccak256, _, _>(data.clone(), l);
			assert_eq!(
				array_bytes::bytes2hex("", proof.root.as_ref()),
				array_bytes::bytes2hex("", root.as_ref())
			);
			assert_eq!(proof.leaf_index, l);
			assert_eq!(&proof.leaf, &data[l]);

			// then
			assert!(verify_proof::<Keccak256, _, _>(
				&proof.root,
				proof.proof,
				data.len(),
				proof.leaf_index,
				&proof.leaf
			));
		}

		let proof = merkle_proof::<Keccak256, _, _>(data.clone(), data.len() - 1);

		assert_eq!(
			proof,
			MerkleProof {
				root,
				proof: vec![
					array_bytes::hex2array_unchecked(
						"340bcb1d49b2d82802ddbcf5b85043edb3427b65d09d7f758fbc76932ad2da2f"
					),
					array_bytes::hex2array_unchecked(
						"ba0580e5bd530bc93d61276df7969fb5b4ae8f1864b4a28c280249575198ff1f"
					),
					array_bytes::hex2array_unchecked(
						"1fad92ed8d0504ef6c0231bbbeeda960a40693f297c64e87b582beb92ecfb00f"
					),
					array_bytes::hex2array_unchecked(
						"0b84c852cbcf839d562d826fd935e1b37975ccaa419e1def8d219df4b83dcbf4"
					),
				],
				number_of_leaves: data.len(),
				leaf_index: data.len() - 1,
				leaf: array_bytes::hex2array_unchecked::<20>(
					"c26B34D375533fFc4c5276282Fa5D660F3d8cbcB"
				)
				.to_vec(),
			}
		);
	}

	#[test]
	fn test_generate_validator_merkle_proof() {
		let public_keys = vec![
			"020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1", // Alice
			"0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27", // Bob
			"0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb", // Charlie
			"03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c", // Dave
			"031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa", // Eve
		];

		let leaves = public_keys
			.into_iter()
			.map(|leaf| beefy_ecdsa_to_ethereum(&hex::decode(leaf).unwrap()))
			.collect::<Vec<_>>();

		let validator_merkle_proof = (0..5usize).fold(vec![], |mut result, idx| {
			let merkle_proof: binary_merkle_tree::MerkleProof<Hash, Vec<u8>> =
				binary_merkle_tree::merkle_proof::<Keccak256, _, _>(leaves.clone(), idx);
			result.push(merkle_proof);
			result
		});
		println!("validator merkle proof : {validator_merkle_proof:?}");
	}

	#[test]
	fn test_hex_and_hex_literal() {
		let left =
			hex_literal::hex!("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1")
				.to_vec();
		let right =
			hex::decode("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1")
				.unwrap();
		assert_eq!(left, right);
	}
}
