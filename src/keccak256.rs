use primitive_types::H256;
use tiny_keccak::{Hasher as _, Keccak};

/// Keccak256 hasher implementation.
pub struct Keccak256;
impl Keccak256 {
	pub fn hash(data: &[u8]) -> H256 {
		let mut keccak = Keccak::v256();
		keccak.update(data);
		let mut output = [0_u8; 32];
		keccak.finalize(&mut output);
		output.into()
	}
}
