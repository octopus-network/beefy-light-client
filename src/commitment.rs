use byteorder::{ByteOrder, LittleEndian};

use super::keccak256::Keccak256;
use primitive_types::H256;

pub type Signature = Vec<u8>;

pub struct Commitment {
	pub payload: H256,
	pub block_number: u64,
	pub validator_set_id: u32,
}

impl Commitment {
	pub fn hash(&self) -> H256 {
		let mut buf = [0_u8; 44];
		buf[0..32].copy_from_slice(self.payload.as_bytes());
		LittleEndian::write_u64(&mut buf[32..40], self.block_number);
		LittleEndian::write_u32(&mut buf[40..44], self.validator_set_id);
		Keccak256::hash(&buf)
	}
}

pub struct SignedCommitment {
	pub commitment: Commitment,
	pub signatures: Vec<Option<Signature>>,
}
