use crate::Hash;
use tiny_keccak::{Hasher as _, Keccak};

use hash256_std_hasher::Hash256StdHasher;
use hash_db::Hasher;

/// Concrete implementation of Hasher using Keccak 256-bit hashes
#[derive(Debug)]
pub struct Keccak256;

impl Hasher for Keccak256 {
	type Out = Hash;
	type StdHasher = Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		let mut keccak = Keccak::v256();
		keccak.update(x);
		let mut output = [0_u8; 32];
		keccak.finalize(&mut output);
		output
	}
}
