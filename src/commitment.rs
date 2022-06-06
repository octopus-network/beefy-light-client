#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::cmp;

#[cfg(feature = "std")]
use std::cmp;

use beefy_merkle_tree::{Hash, Keccak256};
use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{ByteOrder, LittleEndian};
use codec::{Decode, Encode, Input, MaxEncodedLen};
use core::convert::TryInto;
use scale_info::TypeInfo;

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

impl Default for Signature {
	fn default() -> Self {
		Signature([0; 65])
	}
}

impl From<&str> for Signature {
	fn from(hex_str: &str) -> Self {
		let data: [u8; 65] =
			hex::decode(&hex_str[2..]).map_or([0; 65], |s| s.try_into().unwrap_or([0; 65]));
		Self(data)
	}
}

#[derive(
	Debug, Default, Clone, PartialEq, Eq, Encode, Decode, BorshDeserialize, BorshSerialize,
)]
pub struct Commitment {
	pub payload: Hash,
	pub block_number: u32,
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
		let mut buf = [0_u8; 44];
		buf[0..32].copy_from_slice(&self.payload);
		LittleEndian::write_u32(&mut buf[32..36], self.block_number);
		LittleEndian::write_u64(&mut buf[36..44], self.validator_set_id);
		Keccak256::hash(&buf)
	}
}

#[derive(Debug, Default, PartialEq, Eq, Clone, BorshDeserialize, BorshSerialize)]
pub struct SignedCommitment {
	pub commitment: Commitment,
	pub signatures: Vec<Option<Signature>>,
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
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		let temp = CompactSignedCommitment::decode(input)?;
		Ok(CompactSignedCommitment::unpack(temp))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;

	use sp_core::{keccak_256, Pair};
	use sp_keystore::{testing::KeyStore, SyncCryptoStore, SyncCryptoStorePtr};

	/// Key type for BEEFY module.
	pub const KEY_TYPE: sp_application_crypto::KeyTypeId =
		sp_application_crypto::KeyTypeId(*b"beef");

	// The mock signatures are equivalent to the ones produced by the BEEFY keystore
	fn mock_signatures() -> (Signature, Signature) {
		let store: SyncCryptoStorePtr = KeyStore::new().into();

		let alice = sp_core::ecdsa::Pair::from_string("//Alice", None).unwrap();
		let _ =
			SyncCryptoStore::insert_unknown(&*store, KEY_TYPE, "//Alice", alice.public().as_ref())
				.unwrap();

		let msg = keccak_256(b"This is the first message");
		let sig1 = SyncCryptoStore::ecdsa_sign_prehashed(&*store, KEY_TYPE, &alice.public(), &msg)
			.unwrap()
			.unwrap();

		let msg = keccak_256(b"This is the second message");
		let sig2 = SyncCryptoStore::ecdsa_sign_prehashed(&*store, KEY_TYPE, &alice.public(), &msg)
			.unwrap()
			.unwrap();

		(Signature(sig1.0), Signature(sig2.0))
	}

	#[test]
	fn signature_from_hex_str_works() {
		let signature_hex_str = "0x34c47a87fd892a2ed56f7f5708722548f7696578731c1119ba554c73c147433722da580d4daf04f5d13e1f4325a9639ad73aced975084982b5a97546cbf7bcc301";
		let signature: Signature = signature_hex_str.into();
		assert_eq!(signature, Signature(hex!("34c47a87fd892a2ed56f7f5708722548f7696578731c1119ba554c73c147433722da580d4daf04f5d13e1f4325a9639ad73aced975084982b5a97546cbf7bcc301").into()));
	}

	// #[test]
	// fn decode_signed_commitment_works_1() {
	// 	let encoded_signed_commitment = hex!("ea1f52f73f22c9b9ea45b59f36de86e120b8f50b73b963c529584c838336c104a100000000000000000000000401e1b5cf0985f1c6a4d90fc5a050fb586166b0482e995ba1b00b3539097185ab5e7c07832d49a5cddf9b55a838b39eb9224b94077cfb04345788a15219598e858500");

	// 	let signed_commitment = SignedCommitment::decode(&mut &encoded_signed_commitment[..]);

	// 	assert_eq!(signed_commitment.is_ok(), true);
	// }

	#[test]
	fn decode_signed_commitment_works_2() {
		let payload: [u8; 32] = [
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0,
		];

		println!("payload = {:?}", payload);

		let commitment: Commitment = Commitment { payload, block_number: 5, validator_set_id: 0 };

		let sigs = mock_signatures();

		let signed = SignedCommitment {
			commitment,
			signatures: vec![None, None, Some(sigs.0), Some(sigs.1)],
		};

		// when
		let encoded = codec::Encode::encode(&signed);
		let decoded = SignedCommitment::decode(&mut &*encoded);

		println!("decode data = {:?}", decoded);

		// then
		assert_eq!(decoded, Ok(signed));
	}

	#[test]
	fn commitment_ordering() {
		fn commitment(block_number: u32, validator_set_id: u64) -> Commitment {
			Commitment { payload: Hash::default(), block_number, validator_set_id }
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
