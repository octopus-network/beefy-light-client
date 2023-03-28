use crate::Hash;
use hash_db::Hasher;

/// Concrete implementation of Hasher using Keccak 256-bit hashes
#[derive(Debug)]
pub struct Keccak256;

impl Hasher for Keccak256 {
	type Out = Hash;
	type StdHasher = hash256_std_hasher::Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		keccak_256(x)
	}
}

/// Do a keccak 256-bit hash and return result.
pub fn keccak_256(data: &[u8]) -> [u8; 32] {
	use sha3::Digest;
	sha3::Keccak256::digest(data).into()
}
