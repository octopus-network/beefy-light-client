use crate::BeefyNextAuthoritySet;
use beefy_merkle_tree::{Hash, Keccak256};
use codec::Encode;

#[derive(Debug, Default, Encode)]
pub struct MmrLeafVersion(u8);
impl MmrLeafVersion {
	/// Create new version object from `major` and `minor` components.
	///
	/// Panics if any of the component occupies more than 4 bits.
	pub fn new(major: u8, minor: u8) -> Self {
		if major > 0b111 || minor > 0b11111 {
			panic!("Version components are too big.");
		}
		let version = (major << 5) + minor;
		Self(version)
	}

	/// Split the version into `major` and `minor` sub-components.
	pub fn split(&self) -> (u8, u8) {
		let major = self.0 >> 5;
		let minor = self.0 & 0b11111;
		(major, minor)
	}
}

#[derive(Debug, Default, Encode)]
pub struct MmrLeaf {
	/// Version of the leaf format.
	///
	/// Can be used to enable future format migrations and compatibility.
	/// See [`MmrLeafVersion`] documentation for details.
	pub version: MmrLeafVersion,
	/// Current block parent number and hash.
	pub parent_number_and_hash: (u32, Hash),
	/// A merkle root of the next BEEFY authority set.
	pub beefy_next_authority_set: BeefyNextAuthoritySet,
}

impl MmrLeaf {
	pub fn hash(&self) -> Hash {
		Keccak256::hash(&self.encode())
	}
}
