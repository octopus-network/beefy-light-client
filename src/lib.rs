#[cfg(not(feature = "std"))]
use core::result;

use beefy_merkle_tree::{merkle_root, verify_proof, Hash, Keccak256, MerkleProof};
use commitment::{Commitment, SignedCommitment};
use mmr::MmrLeaf;
use validator_set::{BeefyNextAuthoritySet, Public};

pub mod commitment;
pub mod ecdsa;
pub mod mmr;
pub mod simplified_mmr;
pub mod traits;
pub mod validator_set;

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
	InvalidValidatorProof,
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

// $ subkey inspect --scheme ecdsa //Alice
// Secret Key URI `//Alice` is account:
//   Secret seed:       0xcb6df9de1efca7a3998a8ead4e02159d5fa99c3e0d4fd6432667390bb4726854
//   Public key (hex):  0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
//   Public key (SS58): KW39r9CJjAVzmkf9zQ4YDb2hqfAVGdRqn53eRqyruqpxAP5YL
//   Account ID:        0x01e552298e47454041ea31273b4b630c64c104e4514aa3643490b8aaca9cf8ed
//   SS58 Address:      5C7C2Z5sWbytvHpuLTvzKunnnRwQxft1jiqrLD5rhucQ5S9X
//
// justifications.commitment.payload:  0x700a2fb21ba1ec2cdf72bb621846a4cc8628ed8e3ed5bb299f9e36406776f84a
// justifications.commitment.blockNumber:  1369
// justifications.commitment.validatorSetId:  0
// justifications.commitment.hash:  0xd96c73e1a602b757fce3ff4509b57cda4f4989f854dac6753d8d3329049e93e8
// justifications.signatures:  [0x3a481c251a7aa94b89e8160aa9073f74cc24570da13ec9f697a9a7c989943bed31b969b50c47675c11994fbdacb82707293976927922ec8c2124490e417af733]
//
// justifications.commitment.payload:  0x86b1679e44a6a525748707bd2d4d44700fc3a2dc9e152a8fd414b4e9d17b07b5
// justifications.commitment.blockNumber:  1377
// justifications.commitment.validatorSetId:  0
// justifications.commitment.hash:  0x86262696075aeb15493d428a3353c3b60616c8380c0bb4966211a1b92a58634f
// justifications.signatures:  [0xcc73f69bf58fbe1720c59a5f1a804a869012ed9f4e86637cfb85b0d126c86f916f1e7a3db98f2608e4968544fdb0bceb55b380d8c9fd9638ea0c420d47b6001f]
//
// justifications.commitment.payload:  0x3e793b247a32500619702d4d4c6ad63466cc06189904bccd428c17ac2e2b08e2
// justifications.commitment.blockNumber:  1385
// justifications.commitment.validatorSetId:  0
// justifications.commitment.hash:  0x98d3357fa89e5c48f963d76846a526cbd6c40dbd67124b117065af872a1d3ef1
// justifications.signatures:  [0xf994b9bf1410de7988806738ea7c046bbf964cb76d1e07104fd0d5a67925d76558b5cd27e5fc6d566940943f488692fd7bb54233d7e89d34d53dfa16a4b9fb63]
#[derive(Debug, Default)]
pub struct LightClient {
	mmr_root: Hash,
	validator_set: BeefyNextAuthoritySet,
}

// Initialize light client using the BeefyId of the initial validator set.
pub fn new(initial_public_keys: Vec<Public>) -> LightClient {
	LightClient {
		mmr_root: Hash::default(),
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
		signed_commitment: SignedCommitment,
		validator_proof: Vec<MerkleProof<&Public>>,
		mmr_leaf: MmrLeaf,
		mmr_proof: simplified_mmr::MerkleProof,
	) -> Result<(), Error> {
		// TODO: check length
		for proof in validator_proof {
			if !verify_proof::<Keccak256, _, _>(
				&self.validator_set.root,
				proof.proof,
				proof.number_of_leaves,
				proof.leaf_index,
				proof.leaf,
			) {
				return Err(Error::InvalidValidatorProof);
			}
		}
		let commitment = self.verify_commitment(signed_commitment)?;
		self.verify_mmr_leaf(commitment.payload, &mmr_leaf, mmr_proof)?;

		// update mmr_root
		self.mmr_root = commitment.payload;

		// update validator_set
		if mmr_leaf.beefy_next_authority_set.id > self.validator_set.id {
			self.validator_set = mmr_leaf.beefy_next_authority_set;
		}
		Ok(())
	}

	pub fn verify_solochain_message(&self) -> Result<(), Error> {
		Ok(())
	}

	pub fn verify_parachain_message(&self) -> Result<(), Error> {
		Ok(())
	}

	fn verify_commitment(&self, signed_commitment: SignedCommitment) -> Result<Commitment, Error> {
		let SignedCommitment { commitment, signatures } = signed_commitment;
		let commitment_hash = commitment.hash();
		println!("commitment_hash: {:?}", commitment_hash);
		let msg = libsecp256k1::Message::parse_slice(&commitment_hash[..]).unwrap();
		for signature in signatures.into_iter() {
			if let Some(signature) = signature {
				let sig = libsecp256k1::Signature::parse_standard_slice(&signature[..]).unwrap();
				let res =
					libsecp256k1::recover(&msg, &sig, &libsecp256k1::RecoveryId::parse(0).unwrap())
						.unwrap();
				println!("verify result: {:?}", res.serialize_compressed());
			}
		}

		Ok(commitment)
	}

	fn verify_mmr_leaf(
		&self,
		root_hash: Hash,
		leaf: &MmrLeaf,
		proof: simplified_mmr::MerkleProof,
	) -> Result<(), Error> {
		let leaf_hash = leaf.hash();
		let result = simplified_mmr::verify_proof(root_hash, leaf_hash, proof);
		if !result {
			return Err(Error::InvalidMmrProof);
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{Commitment, SignedCommitment};
	use hex_literal::hex;

	#[test]
	fn it_works() {
		let public_keys =
			vec![hex!("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1").into()];
		let lc = new(public_keys);
		println!("{:?}", lc);

		let commitment = Commitment {
			payload: hex!("700a2fb21ba1ec2cdf72bb621846a4cc8628ed8e3ed5bb299f9e36406776f84a")
				.into(),
			block_number: 1369,
			validator_set_id: 0,
		};
		let signed_commitment = SignedCommitment { commitment, signatures: vec![Some(hex!("3a481c251a7aa94b89e8160aa9073f74cc24570da13ec9f697a9a7c989943bed31b969b50c47675c11994fbdacb82707293976927922ec8c2124490e417af733").into())] };
		let res = lc.verify_commitment(signed_commitment).unwrap();
		println!("{:?}", res);

		assert_eq!(2 + 2, 4);
		// let pk = hex!("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1");
		// let pk = libsecp256k1::PublicKey::parse_slice(&pk[..], None).unwrap();
	}
}
