#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use beefy_merkle_tree::{Hash, Keccak256};
use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{ByteOrder, LittleEndian};
use codec::Decode;
use core::convert::TryInto;

/// A signature (a 512-bit value, plus 8 bits for recovery ID).
#[derive(Debug, Decode, PartialEq, Eq)]
pub struct Signature(pub [u8; 65]);

impl From<&str> for Signature {
	fn from(hex_str: &str) -> Self {
		let data: [u8; 65] =
			hex::decode(&hex_str[2..]).map_or([0; 65], |s| s.try_into().unwrap_or([0; 65]));
		Self(data)
	}
}

#[derive(Debug, Clone, Copy, Decode, BorshDeserialize, BorshSerialize)]
pub struct Commitment {
	pub payload: Hash,
	pub block_number: u64,
	pub validator_set_id: u32,
}

impl Commitment {
	pub fn hash(&self) -> Hash {
		let mut buf = [0_u8; 44];
		buf[0..32].copy_from_slice(&self.payload);
		LittleEndian::write_u64(&mut buf[32..40], self.block_number);
		LittleEndian::write_u32(&mut buf[40..44], self.validator_set_id);
		Keccak256::hash(&buf)
	}
}

#[derive(Debug, Decode)]
pub struct SignedCommitment {
	pub commitment: Commitment,
	pub signatures: Vec<Option<Signature>>,
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;

	#[test]
	fn signature_from_hex_str_works() {
		let signature_hex_str = "0x34c47a87fd892a2ed56f7f5708722548f7696578731c1119ba554c73c147433722da580d4daf04f5d13e1f4325a9639ad73aced975084982b5a97546cbf7bcc301";
		let signature: Signature = signature_hex_str.into();
		assert_eq!(signature, Signature(hex!("34c47a87fd892a2ed56f7f5708722548f7696578731c1119ba554c73c147433722da580d4daf04f5d13e1f4325a9639ad73aced975084982b5a97546cbf7bcc301").into()));
	}

	#[test]
	fn decode_signed_commitment_works() {
		let encoded_signed_commitment = hex!("ea1f52f73f22c9b9ea45b59f36de86e120b8f50b73b963c529584c838336c104a100000000000000000000000401e1b5cf0985f1c6a4d90fc5a050fb586166b0482e995ba1b00b3539097185ab5e7c07832d49a5cddf9b55a838b39eb9224b94077cfb04345788a15219598e858500");

		let signed_commitment = SignedCommitment::decode(&mut &encoded_signed_commitment[..]);
		println!("signed_commitment: {:?}", signed_commitment);

		assert_eq!(signed_commitment.is_ok(), true);
	}
}
