#[cfg(not(feature = "std"))]
use alloc::string::String;

use crate::validator_set::ValidatorSetId;
use displaydoc::Display;

#[derive(Debug, PartialEq, Eq, Display)]
pub enum Error {
	/// [Commitment] can't be imported, cause it's signed by either past or future validator set (got validator set `{got}`, expected: `{expected}`).
	InvalidValidatorSetId { expected: ValidatorSetId, got: ValidatorSetId },
	/// [Commitment] can't be imported, cause it's a set transition block and the proof is missing.
	InvalidValidatorProof,
	/// There are too many signatures (got `{got}`, expected: `{expected}`) in the commitment - more than validators.
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
	///
	InvalidMessage,
	///
	InvalidVersionedFinalityProof,
	///
	InvalidCommitmentPayload,
	///
	InvalidRecoveryId,
	///
	WrongSignature,
	///
	InvalidMmrLeafProof,
	///
	DigestNotFound,
	///
	DigestNotMatch,
	///
	HeaderHashNotMatch,
	///
	CantDecodeHeader,
	///
	CantDecodeMmrLeaf,
	///
	CantDecodeMmrProof,
	///
	MissingLatestCommitment,
	///
	CommitmentAlreadyUpdated,
	///
	ValidatorNotFound,
	///
	MissingInProcessState,
	///
	MmrVerifyErr(mmr_lib::Error),
	/// other
	Other(String),
}
