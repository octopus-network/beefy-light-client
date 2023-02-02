#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use hash_db::Hasher;

use crate::{keccak256::Keccak256, BeefyNextAuthoritySet, Hash};
use codec::{Decode, Encode};

#[derive(Clone, Debug, Default, Encode, Decode)]
pub struct MmrLeafVersion(pub u8);
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

#[derive(Clone, Debug, Default, Encode, Decode)]
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
	/// Arbitrary extra leaf data to be used by downstream pallets to include custom data in the
	/// [`MmrLeaf`]
	pub leaf_extra: Vec<u8>,
}

/// A MMR proof data for one of the leaves.
#[derive(Debug, Clone, Default, Encode, Decode)]
pub struct MmrLeafProof {
	/// The index of the leaf the proof is for.
	pub leaf_index: u64,
	/// Number of leaves in MMR, when the proof was generated.
	pub leaf_count: u64,
	/// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
	pub items: Vec<Hash>,
}

/// MMR nodes & size -related utilities.
pub struct NodesUtils {
	no_of_leaves: u64,
}

impl NodesUtils {
	/// Create new instance of MMR nodes utilities for given number of leaves.
	pub fn new(no_of_leaves: u64) -> Self {
		Self { no_of_leaves }
	}

	/// Calculate number of peaks in the MMR.
	pub fn number_of_peaks(&self) -> u64 {
		self.number_of_leaves().count_ones() as u64
	}

	/// Return the number of leaves in the MMR.
	pub fn number_of_leaves(&self) -> u64 {
		self.no_of_leaves
	}

	/// Calculate the total size of MMR (number of nodes).
	pub fn size(&self) -> u64 {
		2 * self.no_of_leaves - self.number_of_peaks()
	}

	/// Calculate maximal depth of the MMR.
	pub fn depth(&self) -> u32 {
		if self.no_of_leaves == 0 {
			return 0
		}

		64 - self.no_of_leaves.next_power_of_two().leading_zeros()
	}
}

struct HashMerger;

impl mmr_lib::Merge for HashMerger {
	type Item = Hash;

	fn merge(left: &Self::Item, right: &Self::Item) -> mmr_lib::Result<Self::Item> {
		let mut combined = [0_u8; 64];
		combined[0..32].copy_from_slice(&left[..]);
		combined[32..64].copy_from_slice(&right[..]);

		Ok(Keccak256::hash(&combined))
	}
}

/// Stateless verification of the leaf proof.
pub fn verify_leaf_proof(
	root: Hash,
	leaf_hash: Hash,
	proof: MmrLeafProof,
) -> Result<bool, crate::Error> {
	let size = NodesUtils::new(proof.leaf_count).size();
	let leaf_position = mmr_lib::leaf_index_to_pos(proof.leaf_index);

	let p = mmr_lib::MerkleProof::<Hash, HashMerger>::new(size, proof.items);
	p.verify(root, vec![(leaf_position, leaf_hash)])
		.map_err(|_| crate::Error::InvalidMmrLeafProof)
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;

	#[test]
	fn verify_leaf_proof_works_1() {
		let leaves: Vec<Hash> = vec![
			hex!("4320435e8c3318562dba60116bdbcc0b82ffcecb9bb39aae3300cfda3ad0b8b0").into(),
			hex!("ad4cbc033833612ccd4626d5f023b9dfc50a35e838514dd1f3c86f8506728705").into(),
			hex!("9ba3bd51dcd2547a0155cf13411beeed4e2b640163bbea02806984f3fcbf822e").into(),
			hex!("1b14c1dc7d3e4def11acdf31be0584f4b85c3673f1ff72a3af467b69a3b0d9d0").into(),
			hex!("3b031d22e24f1126c8f7d2f394b663f9b960ed7abbedb7152e17ce16112656d0").into(),
			hex!("8ed25570209d8f753d02df07c1884ddb36a3d9d4770e4608b188322151c657fe").into(),
			hex!("611c2174c6164952a66d985cfe1ec1a623794393e3acff96b136d198f37a648c").into(),
			hex!("1e959bd2b05d662f179a714fbf58928730380ad8579a966a9314c8e13b735b13").into(),
			hex!("1c69edb31a1f805991e8e0c27d9c4f5f7fbb047c3313385fd9f4088d60d3d12b").into(),
			hex!("0a4098f56c2e74557cf95f4e9bdc32e7445dd3c7458766c807cd6b54b89e8b38").into(),
			hex!("79501646d325333e636b557abefdfb6fa688012eef0b57bd0b93ef368ff86833").into(),
			hex!("251054c04fcdeca1058dd511274b5eeb22c04b76a3c80f92a989cec535abbd5e").into(),
			hex!("9b2645185bbf36ecfd425c4f99596107d78d160cea01b428be0b079ec8bf2a85").into(),
			hex!("9a9ca4381b27601fe46fe517eb2eedffd8b14d7140cb10fec111337968c0dd28").into(),
			hex!("c43faffd065ac4fc5bc432ad45c13de341b233dcc55afe99ac05eef2fbb8a583").into(),
		];

		let root: Hash =
			hex!("3e81e73a77ddf45c0252bba8d1195d1076003d8387df373a46a3a559bc06acca").into();

		let proofs = vec![
			MmrLeafProof {
				leaf_index: 0,
				leaf_count: 15,
				items: vec![
					hex!("ad4cbc033833612ccd4626d5f023b9dfc50a35e838514dd1f3c86f8506728705").into(),
					hex!("cb24f4614ad5b2a5430344c99545b421d9af83c46fd632d70a332200884b4d46").into(),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 1,
				leaf_count: 15,
				items: vec![
					hex!("4320435e8c3318562dba60116bdbcc0b82ffcecb9bb39aae3300cfda3ad0b8b0").into(),
					hex!("cb24f4614ad5b2a5430344c99545b421d9af83c46fd632d70a332200884b4d46").into(),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 2,
				leaf_count: 15,
				items: vec![
					hex!("1b14c1dc7d3e4def11acdf31be0584f4b85c3673f1ff72a3af467b69a3b0d9d0").into(),
					hex!("672c04a9cd05a644789d769daa552d35d8de7c33129f8a7cbf49e595234c4854").into(),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 3,
				leaf_count: 15,
				items: vec![
					hex!("9ba3bd51dcd2547a0155cf13411beeed4e2b640163bbea02806984f3fcbf822e").into(),
					hex!("672c04a9cd05a644789d769daa552d35d8de7c33129f8a7cbf49e595234c4854").into(),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 4,
				leaf_count: 15,
				items: vec![
					hex!("8ed25570209d8f753d02df07c1884ddb36a3d9d4770e4608b188322151c657fe").into(),
					hex!("421865424d009fee681cc1e439d9bd4cce0a6f3e79cce0165830515c644d95d4").into(),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 5,
				leaf_count: 15,
				items: vec![
					hex!("3b031d22e24f1126c8f7d2f394b663f9b960ed7abbedb7152e17ce16112656d0").into(),
					hex!("421865424d009fee681cc1e439d9bd4cce0a6f3e79cce0165830515c644d95d4").into(),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 6,
				leaf_count: 15,
				items: vec![
					hex!("1e959bd2b05d662f179a714fbf58928730380ad8579a966a9314c8e13b735b13").into(),
					hex!("7e4316ae2ebf7c3b6821cb3a46ca8b7a4f9351a9b40fcf014bb0a4fd8e8f29da").into(),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 7,
				leaf_count: 15,
				items: vec![
					hex!("611c2174c6164952a66d985cfe1ec1a623794393e3acff96b136d198f37a648c").into(),
					hex!("7e4316ae2ebf7c3b6821cb3a46ca8b7a4f9351a9b40fcf014bb0a4fd8e8f29da").into(),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252").into(),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 8,
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3").into(),
					hex!("0a4098f56c2e74557cf95f4e9bdc32e7445dd3c7458766c807cd6b54b89e8b38").into(),
					hex!("7d1f24a6c60769cc6bdc9fc123848d36ef2c6c48e84d9dd464d153cbb0e7ae76").into(),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 9,
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3").into(),
					hex!("1c69edb31a1f805991e8e0c27d9c4f5f7fbb047c3313385fd9f4088d60d3d12b").into(),
					hex!("7d1f24a6c60769cc6bdc9fc123848d36ef2c6c48e84d9dd464d153cbb0e7ae76").into(),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 10,
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3").into(),
					hex!("251054c04fcdeca1058dd511274b5eeb22c04b76a3c80f92a989cec535abbd5e").into(),
					hex!("2c6280fdcaf131531fe103e0e7353a77440333733c68effa4d3c49413c00b55f").into(),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 11,
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3").into(),
					hex!("79501646d325333e636b557abefdfb6fa688012eef0b57bd0b93ef368ff86833").into(),
					hex!("2c6280fdcaf131531fe103e0e7353a77440333733c68effa4d3c49413c00b55f").into(),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 12,
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3").into(),
					hex!("f323ac1a7f56de5f40ed8df3e97af74eec0ee9d72883679e49122ffad2ffd03b").into(),
					hex!("9a9ca4381b27601fe46fe517eb2eedffd8b14d7140cb10fec111337968c0dd28").into(),
					hex!("c43faffd065ac4fc5bc432ad45c13de341b233dcc55afe99ac05eef2fbb8a583").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 13,
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3").into(),
					hex!("f323ac1a7f56de5f40ed8df3e97af74eec0ee9d72883679e49122ffad2ffd03b").into(),
					hex!("9b2645185bbf36ecfd425c4f99596107d78d160cea01b428be0b079ec8bf2a85").into(),
					hex!("c43faffd065ac4fc5bc432ad45c13de341b233dcc55afe99ac05eef2fbb8a583").into(),
				],
			},
			MmrLeafProof {
				leaf_index: 14,
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3").into(),
					hex!("f323ac1a7f56de5f40ed8df3e97af74eec0ee9d72883679e49122ffad2ffd03b").into(),
					hex!("a0d0a78fe68bd0af051c24c6f0ddd219594b582fa3147570b8fd60cf1914efb4").into(),
				],
			},
		];

		for i in 0..leaves.len() {
			assert_eq!(verify_leaf_proof(root, leaves[i].clone(), proofs[i].clone()), Ok(true));
		}
	}
}
