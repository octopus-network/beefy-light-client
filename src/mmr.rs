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

// https://github.com/paritytech/substrate/blob/dec0369a35893c2be432e74358c4c7039e1e57be/primitives/merkle-mountain-range/src/lib.rs#L355
/// A MMR proof data for one of the leaves.
#[derive(Debug, Clone, Default, Encode, Decode)]
pub struct MmrLeafProof {
	/// The index of the leaf the proof is for.
	pub leaf_indices: Vec<u64>,
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
	leaves: Vec<Hash>,
	proof: MmrLeafProof,
) -> Result<bool, crate::Error> {
	let size = NodesUtils::new(proof.leaf_count).size();
	if leaves.len() != proof.leaf_indices.len() {
		return Err(crate::Error::Other(
			"Proof leaf_indices not same length with leaves".to_string(),
		))
	}
	let leaves_positions_and_data = proof
		.leaf_indices
		.into_iter()
		.map(mmr_lib::leaf_index_to_pos)
		.zip(leaves.into_iter())
		.collect();

	let p = mmr_lib::MerkleProof::<Hash, HashMerger>::new(size, proof.items);
	p.verify(root, leaves_positions_and_data).map_err(crate::Error::MmrVerifyErr)
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;

	#[test]
	fn test_decode_mmr_leaf_and_mmr_leaf_proof() {
		// block number is 1280, best block number is 1281
		// 		{
		//   blockHash: 0x22b2d813abf9ed4c60936b8a37ff605156ecb2c8b90e361d59dd772b88202ec5
		//   leaves: 0x04c50100ff04000075728f50649a47e581d32e4999ec5300fb686335bb7551bb31896a1c2d32bd0c800000000000000002000000697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce4020000000000000000000000000000000000000000000000000000000000000000
		//   proof: 0x04ff0400000000000001050000000000002822fb7de1e60f95a7547c93d810b9b809edb7c8300557c92ff76751090ed1390c0270f0920729a38f595148820d6434ee486e744db906d99ce8b51697f3b4c57cb50b54d3bae7267c680a731f14fd46174c2869262ba89f9fb3eb147ddf0e91b0372b66f27040106b14d62307a379a9a830badf9a11cb63c823728e6be25243cd41a7a240d003f60195e7733a6030770ebe63a418d6b26f571200bb0ab73d9dc15406276ac0832c6685323b59d542e3164e4a97ae78a028d4577294144609fa49bcdd057ee3f18a76f1df6c258350a1538516bb00e21fc6c9b36c120c371e7776f6919a04f759ac4093037dad5353f6991937da1131b8172eb8594a231367eba3486edae9c03401d5d4e5f822c6caeef8254a01369288bb1e5efb7257234221cc091b03a1c8074e3793da6d0e9f0c67932d0ed7962367064eb5f215dabdd495a7
		// }
		// let  encoded_mmr_leaf = hex!("04c50100ff04000075728f50649a47e581d32e4999ec5300fb686335bb7551bb31896a1c2d32bd0c800000000000000002000000697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce4020000000000000000000000000000000000000000000000000000000000000000");

		// let leaf: Vec<MmrLeaf> = Decode::decode(&mut &encoded_mmr_leaf[..]).unwrap();
		// let mmr_leaf_vector: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
		// println!("mmr_leaf_vector: {leaf:?}");
	}
	#[test]
	fn verify_leaf_proof_works_1() {
		let leaves: Vec<Hash> = vec![
			hex!("4320435e8c3318562dba60116bdbcc0b82ffcecb9bb39aae3300cfda3ad0b8b0"),
			hex!("ad4cbc033833612ccd4626d5f023b9dfc50a35e838514dd1f3c86f8506728705"),
			hex!("9ba3bd51dcd2547a0155cf13411beeed4e2b640163bbea02806984f3fcbf822e"),
			hex!("1b14c1dc7d3e4def11acdf31be0584f4b85c3673f1ff72a3af467b69a3b0d9d0"),
			hex!("3b031d22e24f1126c8f7d2f394b663f9b960ed7abbedb7152e17ce16112656d0"),
			hex!("8ed25570209d8f753d02df07c1884ddb36a3d9d4770e4608b188322151c657fe"),
			hex!("611c2174c6164952a66d985cfe1ec1a623794393e3acff96b136d198f37a648c"),
			hex!("1e959bd2b05d662f179a714fbf58928730380ad8579a966a9314c8e13b735b13"),
			hex!("1c69edb31a1f805991e8e0c27d9c4f5f7fbb047c3313385fd9f4088d60d3d12b"),
			hex!("0a4098f56c2e74557cf95f4e9bdc32e7445dd3c7458766c807cd6b54b89e8b38"),
			hex!("79501646d325333e636b557abefdfb6fa688012eef0b57bd0b93ef368ff86833"),
			hex!("251054c04fcdeca1058dd511274b5eeb22c04b76a3c80f92a989cec535abbd5e"),
			hex!("9b2645185bbf36ecfd425c4f99596107d78d160cea01b428be0b079ec8bf2a85"),
			hex!("9a9ca4381b27601fe46fe517eb2eedffd8b14d7140cb10fec111337968c0dd28"),
			hex!("c43faffd065ac4fc5bc432ad45c13de341b233dcc55afe99ac05eef2fbb8a583"),
		];

		let root: Hash = hex!("3e81e73a77ddf45c0252bba8d1195d1076003d8387df373a46a3a559bc06acca");

		let proofs = vec![
			MmrLeafProof {
				leaf_indices: vec![0],
				leaf_count: 15,
				items: vec![
					hex!("ad4cbc033833612ccd4626d5f023b9dfc50a35e838514dd1f3c86f8506728705"),
					hex!("cb24f4614ad5b2a5430344c99545b421d9af83c46fd632d70a332200884b4d46"),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![1],
				leaf_count: 15,
				items: vec![
					hex!("4320435e8c3318562dba60116bdbcc0b82ffcecb9bb39aae3300cfda3ad0b8b0"),
					hex!("cb24f4614ad5b2a5430344c99545b421d9af83c46fd632d70a332200884b4d46"),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![2],
				leaf_count: 15,
				items: vec![
					hex!("1b14c1dc7d3e4def11acdf31be0584f4b85c3673f1ff72a3af467b69a3b0d9d0"),
					hex!("672c04a9cd05a644789d769daa552d35d8de7c33129f8a7cbf49e595234c4854"),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![3],
				leaf_count: 15,
				items: vec![
					hex!("9ba3bd51dcd2547a0155cf13411beeed4e2b640163bbea02806984f3fcbf822e"),
					hex!("672c04a9cd05a644789d769daa552d35d8de7c33129f8a7cbf49e595234c4854"),
					hex!("441bf63abc7cf9b9e82eb57b8111c883d50ae468d9fd7f301e12269fc0fa1e75"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![4],
				leaf_count: 15,
				items: vec![
					hex!("8ed25570209d8f753d02df07c1884ddb36a3d9d4770e4608b188322151c657fe"),
					hex!("421865424d009fee681cc1e439d9bd4cce0a6f3e79cce0165830515c644d95d4"),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![5],
				leaf_count: 15,
				items: vec![
					hex!("3b031d22e24f1126c8f7d2f394b663f9b960ed7abbedb7152e17ce16112656d0"),
					hex!("421865424d009fee681cc1e439d9bd4cce0a6f3e79cce0165830515c644d95d4"),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![6],
				leaf_count: 15,
				items: vec![
					hex!("1e959bd2b05d662f179a714fbf58928730380ad8579a966a9314c8e13b735b13"),
					hex!("7e4316ae2ebf7c3b6821cb3a46ca8b7a4f9351a9b40fcf014bb0a4fd8e8f29da"),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![7],
				leaf_count: 15,
				items: vec![
					hex!("611c2174c6164952a66d985cfe1ec1a623794393e3acff96b136d198f37a648c"),
					hex!("7e4316ae2ebf7c3b6821cb3a46ca8b7a4f9351a9b40fcf014bb0a4fd8e8f29da"),
					hex!("ae88a0825da50e953e7a359c55fe13c8015e48d03d301b8bdfc9193874da9252"),
					hex!("de783edd9fe65db4ce28c56687da424218086b4948185bdd9f685a42506e3ba2"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![8],
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3"),
					hex!("0a4098f56c2e74557cf95f4e9bdc32e7445dd3c7458766c807cd6b54b89e8b38"),
					hex!("7d1f24a6c60769cc6bdc9fc123848d36ef2c6c48e84d9dd464d153cbb0e7ae76"),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![9],
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3"),
					hex!("1c69edb31a1f805991e8e0c27d9c4f5f7fbb047c3313385fd9f4088d60d3d12b"),
					hex!("7d1f24a6c60769cc6bdc9fc123848d36ef2c6c48e84d9dd464d153cbb0e7ae76"),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![10],
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3"),
					hex!("251054c04fcdeca1058dd511274b5eeb22c04b76a3c80f92a989cec535abbd5e"),
					hex!("2c6280fdcaf131531fe103e0e7353a77440333733c68effa4d3c49413c00b55f"),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![11],
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3"),
					hex!("79501646d325333e636b557abefdfb6fa688012eef0b57bd0b93ef368ff86833"),
					hex!("2c6280fdcaf131531fe103e0e7353a77440333733c68effa4d3c49413c00b55f"),
					hex!("24a44d3d08fbb13a1902e9fa3995456e9a141e0960a2f59725e65a37d474f2c0"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![12],
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3"),
					hex!("f323ac1a7f56de5f40ed8df3e97af74eec0ee9d72883679e49122ffad2ffd03b"),
					hex!("9a9ca4381b27601fe46fe517eb2eedffd8b14d7140cb10fec111337968c0dd28"),
					hex!("c43faffd065ac4fc5bc432ad45c13de341b233dcc55afe99ac05eef2fbb8a583"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![13],
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3"),
					hex!("f323ac1a7f56de5f40ed8df3e97af74eec0ee9d72883679e49122ffad2ffd03b"),
					hex!("9b2645185bbf36ecfd425c4f99596107d78d160cea01b428be0b079ec8bf2a85"),
					hex!("c43faffd065ac4fc5bc432ad45c13de341b233dcc55afe99ac05eef2fbb8a583"),
				],
			},
			MmrLeafProof {
				leaf_indices: vec![14],
				leaf_count: 15,
				items: vec![
					hex!("73d1bf5a0b1329cd526fba68bb89504258fec5a2282001167fd51c89f7ef73d3"),
					hex!("f323ac1a7f56de5f40ed8df3e97af74eec0ee9d72883679e49122ffad2ffd03b"),
					hex!("a0d0a78fe68bd0af051c24c6f0ddd219594b582fa3147570b8fd60cf1914efb4"),
				],
			},
		];

		for i in 0..leaves.len() {
			assert_eq!(verify_leaf_proof(root, vec![leaves[i]], proofs[i].clone()), Ok(true));
		}
	}
}
