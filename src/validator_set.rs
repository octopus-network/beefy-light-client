use borsh::{BorshDeserialize, BorshSerialize};
use codec::{Decode, Encode};

/// A typedef for validator set id.
pub type ValidatorSetId = u64;

// ref: https://github.com/paritytech/substrate/blob/49ba186c53c24a3ace99c55ecd75370d8e65da1f/primitives/consensus/beefy/src/mmr.rs#L105
#[derive(
	Clone, Debug, Default, Encode, Decode, BorshDeserialize, BorshSerialize, PartialEq, Eq,
)]
pub struct BeefyNextAuthoritySet<MerkleRoot> {
	/// Id of the next set.
	///
	/// Id is required to correlate BEEFY signed commitments with the validator set.
	/// Light Client can easily verify that the commitment witness it is getting is
	/// produced by the latest validator set.
	pub id: ValidatorSetId,
	/// Number of validators in the set.
	///
	/// Some BEEFY Light Clients may use an interactive protocol to verify only subset
	/// of signatures. We put set length here, so that these clients can verify the minimal
	/// number of required signatures.
	pub len: u32,
	/// Merkle Root Hash build from BEEFY AuthorityIds.
	///
	/// This is used by Light Clients to confirm that the commitments are signed by the correct
	/// validator set. Light Clients using interactive protocol, might verify only subset of
	/// signatures, hence don't require the full list here (will receive inclusion proofs).
	pub root: MerkleRoot,
}
