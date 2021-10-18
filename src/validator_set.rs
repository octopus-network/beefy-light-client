use codec::{Decode, Encode};

use primitive_types::H256;

/// A typedef for validator set id.
pub type ValidatorSetId = u64;

/// A set of BEEFY authorities, a.k.a. validators.
#[derive(Decode, Encode, Debug, PartialEq, Clone)]
pub struct ValidatorSet {
	/// Public keys of the validator set elements
	pub validators: Vec<H256>,
	/// Identifier of the validator set
	pub id: ValidatorSetId,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Public(pub u8);

impl From<u8> for Public {
	fn from(public: u8) -> Self {
		Self(public)
	}
}

#[derive(Debug)]
pub enum Signature {
	ValidFor(Public),
	Invalid,
}

impl Signature {
	pub fn is_valid_for(&self, public: &Public) -> bool {
		matches!(self, Self::ValidFor(ref p) if p == public)
	}
}
