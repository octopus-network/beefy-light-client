#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::cmp;

#[cfg(feature = "std")]
use std::cmp;

use beefy_merkle_tree::{Hash, Keccak256};
use borsh::{BorshDeserialize, BorshSerialize};
use codec::{Decode, Encode, Error, Input, MaxEncodedLen};
use core::convert::TryInto;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};

/// A signature (a 512-bit value, plus 8 bits for recovery ID).
#[derive(
	Debug,
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	BorshDeserialize,
	BorshSerialize,
	TypeInfo,
	MaxEncodedLen,
)]
pub struct Signature(pub [u8; 65]);

impl From<&str> for Signature {
	fn from(hex_str: &str) -> Self {
		let data: [u8; 65] =
			hex::decode(&hex_str[2..]).map_or([0; 65], |s| s.try_into().unwrap_or([0; 65]));
		Self(data)
	}
}

/// Id of different payloads in the [`Commitment`] data
pub type BeefyPayloadId = [u8; 2];

/// Registry of all known [`BeefyPayloadId`].
pub mod known_payload_ids {
	use crate::BeefyPayloadId;

	/// A [`Payload`](super::Payload) identifier for Merkle Mountain Range root hash.
	///
	/// Encoded value should contain a [`crate::MmrRootHash`] type (i.e. 32-bytes hash).
	pub const MMR_ROOT_ID: BeefyPayloadId = *b"mh";
}

/// A BEEFY payload type allowing for future extensibility of adding additional kinds of payloads.
///
/// The idea is to store a vector of SCALE-encoded values with an extra identifier.
/// Identifiers MUST be sorted by the [`BeefyPayloadId`] to allow efficient lookup of expected
/// value. Duplicated identifiers are disallowed. It's okay for different implementations to only
/// support a subset of possible values.
#[derive(
	Decode,
	Encode,
	Debug,
	PartialEq,
	Eq,
	Clone,
	Ord,
	PartialOrd,
	BorshDeserialize,
	BorshSerialize,
	Serialize,
	Deserialize,
)]
pub struct Payload(pub Vec<(BeefyPayloadId, Vec<u8>)>);

impl Payload {
	/// Construct a new payload given an initial vallue
	pub fn new(id: BeefyPayloadId, value: Vec<u8>) -> Self {
		Self(vec![(id, value)])
	}

	/// Returns a raw payload under given `id`.
	///
	/// If the [`BeefyPayloadId`] is not found in the payload `None` is returned.
	pub fn get_raw(&self, id: &BeefyPayloadId) -> Option<&Vec<u8>> {
		let index = self.0.binary_search_by(|probe| probe.0.cmp(id)).ok()?;
		Some(&self.0[index].1)
	}

	/// Returns a decoded payload value under given `id`.
	///
	/// In case the value is not there or it cannot be decoded does not match `None` is returned.
	pub fn get_decoded<T: Decode>(&self, id: &BeefyPayloadId) -> Option<T> {
		self.get_raw(id).and_then(|raw| T::decode(&mut &raw[..]).ok())
	}

	/// Push a `Vec<u8>` with a given id into the payload vec.
	/// This method will internally sort the payload vec after every push.
	///
	/// Returns self to allow for daisy chaining.
	pub fn push_raw(mut self, id: BeefyPayloadId, value: Vec<u8>) -> Self {
		self.0.push((id, value));
		self.0.sort_by_key(|(id, _)| *id);
		self
	}
}

/// A commitment signed by GRANDPA validators as part of BEEFY protocol.
///
/// The commitment contains a [payload](Commitment::payload) extracted from the finalized block at
/// height [block_number](Commitment::block_number).
/// GRANDPA validators collect signatures on commitments and a stream of such signed commitments
/// (see [SignedCommitment]) forms the BEEFY protocol.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, BorshDeserialize, BorshSerialize)]
pub struct Commitment {
	///  A collection of payloads to be signed, see [`Payload`] for details.
	///
	/// One of the payloads should be some form of cumulative representation of the chain (think
	/// MMR root hash). Additionally one of the payloads should also contain some details that
	/// allow the light client to verify next validator set. The protocol does not enforce any
	/// particular format of this data, nor how often it should be present in commitments, however
	/// the light client has to be provided with full validator set whenever it performs the
	/// transition (i.e. importing first block with
	/// [validator_set_id](Commitment::validator_set_id) incremented).
	pub payload: Payload,

	/// Finalized block number this commitment is for.
	///
	/// GRANDPA validators agree on a block they create a commitment for and start collecting
	/// signatures. This process is called a round.
	/// There might be multiple rounds in progress (depending on the block choice rule), however
	/// since the payload is supposed to be cumulative, it is not required to import all
	/// commitments.
	/// BEEFY light client is expected to import at least one commitment per epoch,
	/// but is free to import as many as it requires.
	pub block_number: u32,

	/// BEEFY validator set supposed to sign this commitment.
	///
	/// Validator set is changing once per epoch. The Light Client must be provided by details
	/// about the validator set whenever it's importing first commitment with a new
	/// `validator_set_id`. Validator set data MUST be verifiable, for instance using
	/// [payload](Commitment::payload) information.
	pub validator_set_id: u64,
}

impl cmp::PartialOrd for Commitment {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl cmp::Ord for Commitment {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.validator_set_id
			.cmp(&other.validator_set_id)
			.then_with(|| self.block_number.cmp(&other.block_number))
	}
}

impl Commitment {
	pub fn hash(&self) -> Hash {
		Keccak256::hash(&self.encode())
	}
}

/// A commitment with matching GRANDPA validators' signatures.
///
/// Note that SCALE-encoding of the structure is optimized for size efficiency over the wire,
/// please take a look at custom [`Encode`] and [`Decode`] implementations and
/// `CompactSignedCommitment` struct.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct SignedCommitment {
	/// The commitment signatures are collected for.
	pub commitment: Commitment,
	/// GRANDPA validators' signatures for the commitment.
	///
	/// The length of this `Vec` must match number of validators in the current set (see
	/// [Commitment::validator_set_id]).
	pub signatures: Vec<Option<Signature>>,
}

impl SignedCommitment {
	/// Return the number of collected signatures.
	pub fn no_of_signatures(&self) -> usize {
		self.signatures.iter().filter(|x| x.is_some()).count()
	}
}

/// Type to be used to denote placement of signatures
type BitField = Vec<u8>;
/// Compress 8 bit values into a single u8 Byte
const CONTAINER_BIT_SIZE: usize = 8;

/// Compressed representation of [`SignedCommitment`], used for encoding efficiency.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct CompactSignedCommitment {
	/// The commitment, unchanged compared to regular [`SignedCommitment`].
	commitment: Commitment,
	/// A bitfield representing presence of a signature coming from a validator at some index.
	///
	/// The bit at index `0` is set to `1` in case we have a signature coming from a validator at
	/// index `0` in in the original validator set. In case the [`SignedCommitment`] does not
	/// contain that signature the `bit` will be set to `0`. Bits are packed into `Vec<u8>`
	signatures_from: BitField,
	/// Number of validators in the Validator Set and hence number of significant bits in the
	/// [`signatures_from`] collection.
	///
	/// Note this might be smaller than the size of `signatures_compact` in case some signatures
	/// are missing.
	validator_set_len: u32,
	/// A `Vec` containing all `Signature`s present in the original [`SignedCommitment`].
	///
	/// Note that in order to associate a `Signature` from this `Vec` with a validator, one needs
	/// to look at the `signatures_from` bitfield, since some validators might have not produced a
	/// signature.
	signatures_compact: Vec<Signature>,
}

impl CompactSignedCommitment {
	/// Packs a `SignedCommitment` into the compressed `CompactSignedCommitment` format for
	/// efficient network transport.
	fn pack(signed_commitment: &SignedCommitment) -> Self {
		let SignedCommitment { commitment, signatures } = signed_commitment;
		let validator_set_len = signatures.len() as u32;

		let signatures_compact: Vec<Signature> =
			signatures.iter().filter_map(|x| x.clone()).collect();
		let bits = {
			let mut bits: Vec<u8> =
				signatures.iter().map(|x| if x.is_some() { 1 } else { 0 }).collect();
			// Resize with excess bits for placement purposes
			let excess_bits_len =
				CONTAINER_BIT_SIZE - (validator_set_len as usize % CONTAINER_BIT_SIZE);
			bits.resize(bits.len() + excess_bits_len, 0);
			bits
		};

		let mut signatures_from: BitField = vec![];
		let chunks = bits.chunks(CONTAINER_BIT_SIZE);
		for chunk in chunks {
			let mut iter = chunk.iter().copied();
			let mut v = iter.next().unwrap() as u8;

			for bit in iter {
				v <<= 1;
				v |= bit as u8;
			}

			signatures_from.push(v);
		}

		Self {
			commitment: commitment.clone(),
			signatures_from,
			validator_set_len,
			signatures_compact,
		}
	}

	/// Unpacks a `CompactSignedCommitment` into the uncompressed `SignedCommitment` form.
	fn unpack(temporary_signatures: CompactSignedCommitment) -> SignedCommitment {
		let CompactSignedCommitment {
			commitment,
			signatures_from,
			validator_set_len,
			signatures_compact,
		} = temporary_signatures;
		let mut bits: Vec<u8> = vec![];

		for block in signatures_from {
			for bit in 0..CONTAINER_BIT_SIZE {
				bits.push((block >> (CONTAINER_BIT_SIZE - bit - 1)) & 1);
			}
		}

		bits.truncate(validator_set_len as usize);

		let mut next_signature = signatures_compact.into_iter();
		let signatures: Vec<Option<Signature>> = bits
			.iter()
			.map(|&x| if x == 1 { next_signature.next() } else { None })
			.collect();

		SignedCommitment { commitment, signatures }
	}
}

impl Encode for SignedCommitment {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		let temp = CompactSignedCommitment::pack(self);
		temp.using_encoded(f)
	}
}

impl Decode for SignedCommitment {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let temp = CompactSignedCommitment::decode(input)?;
		Ok(CompactSignedCommitment::unpack(temp))
	}
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
	fn decode_signed_commitment_works_1() {
		let encoded_signed_commitment = hex!(
                        "046d68343048656c6c6f20576f726c6421050000000000000000000000000000000000000000000000
                        04300400000008558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba012d6e1f8105c337a86cdd9a
                        aacdc496577f3db8c55ef9e6fd48f2c5c05a2274707491635d8ba3df64f324575b7b2a34487bca2324b
                        6a0046395a71681be3d0c2a00"
		);

		let signed_commitment = SignedCommitment::decode(&mut &encoded_signed_commitment[..]);

		assert_eq!(signed_commitment.is_ok(), true);
	}

	#[test]
	fn decode_signed_commitment_works_2() {
		let encoded_signed_commitment = hex!(
                        "046d68343048656c6c6f20576f726c6421050000000000000000000000000000000000000000000000
                        05020000000000000000000000000000000000000000000000000000000000000000000000000000000
                        000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                        fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                        fffffffffff0000040000b10a558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb
                        75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86
                        e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c7
                        46cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795c
                        c985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68c
                        e3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09ab
                        ed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8
                        1279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314
                        d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107
                        b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba
                        01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5
                        e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d
                        72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99
                        bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746c
                        c321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98
                        5580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3d
                        c0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4
                        da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad8127
                        9df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10
                        dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2a
                        c80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015
                        58455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99
                        a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d
                        948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb
                        7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc32
                        1f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc98558
                        0e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c
                        33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8
                        480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df
                        0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3
                        cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80
                        a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba015584
                        55ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a83
                        0e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948
                        d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb781
                        6f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2
                        319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4
                        fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c
                        86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480
                        c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df079
                        5cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd6
                        8ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09
                        abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455a
                        d81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e3
                        14d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d11
                        07b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9
                        ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319
                        a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb7
                        5d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e
                        99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c74
                        6cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc
                        985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce
                        3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abe
                        d4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81
                        279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d
                        10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b
                        2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0
                        1558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e
                        99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d7
                        2d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99b
                        cb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc
                        321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985
                        580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc
                        0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4d
                        a8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279
                        df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10d
                        d3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac
                        80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155
                        8455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a
                        830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d9
                        48d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7
                        816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321
                        f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580
                        e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c3
                        3c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da84
                        80c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0
                        795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3c
                        d68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a
                        09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba0155845
                        5ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830
                        e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d
                        1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816
                        f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f23
                        19a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4f
                        b75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c8
                        6e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c
                        746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795
                        cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68
                        ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09a
                        bed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad
                        81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e31
                        4d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d110
                        7b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9b
                        a01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a
                        5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75
                        d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e9
                        9bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746
                        cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9
                        85580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3
                        dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed
                        4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad812
                        79df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d1
                        0dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2
                        ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01
                        558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e9
                        9a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72
                        d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bc
                        b7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc3
                        21f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc9855
                        80e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0
                        c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da
                        8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279d
                        f0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd
                        3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac8
                        0a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558
                        455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a8
                        30e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d94
                        8d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb78
                        16f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f
                        2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e
                        4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33
                        c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da848
                        0c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df07
                        95cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd
                        68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a0
                        9abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455
                        ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f2319a5e99a830e
                        314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01558455ad81279df0795cc985580e4fb75d72d948d1
                        107b2ac80a09abed4da8480c746cc321f2319a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f
                        9ba01558455ad81279df0795cc985580e4fb75d72d948d1107b2ac80a09abed4da8480c746cc321f231
                        9a5e99a830e314d10dd3cd68ce3dc0c33c86e99bcb7816f9ba01"
			);

		let signed_commitment = SignedCommitment::decode(&mut &encoded_signed_commitment[..]);

		assert_eq!(signed_commitment.is_ok(), true);
	}

	#[test]
	fn commitment_ordering() {
		fn commitment(block_number: u32, validator_set_id: u64) -> Commitment {
			let payload = Payload::new(known_payload_ids::MMR_ROOT_ID, "Hello World!".encode());
			Commitment { payload, block_number, validator_set_id }
		}

		// given
		let a = commitment(1, 0);
		let b = commitment(2, 1);
		let c = commitment(10, 0);
		let d = commitment(10, 1);

		// then
		assert!(a < b);
		assert!(a < c);
		assert!(c < b);
		assert!(c < d);
		assert!(b < d);
	}
}
