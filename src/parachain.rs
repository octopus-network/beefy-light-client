use crate::{
	commitment::known_payload_ids::MMR_ROOT_ID,
	header::Header,
	mmr::{HashMerger, MmrLeaf, MmrLeafVersion, NodesUtils},
	validator_set::BeefyNextAuthoritySet,
	Error, Hash, LightClient,
};
use codec::{Decode, Encode};
use hash_db::Hasher;
use sp_core::H256;
use sp_runtime::traits::Keccak256;

#[derive(sp_std::fmt::Debug, Clone, PartialEq, Eq, Encode, Decode)]
/// Parachain headers update with proof
pub struct ParachainsUpdateProof {
	/// Parachain headers
	pub parachain_headers: Vec<ParachainHeader>,
	/// Mmr Batch proof for parachain headers
	pub mmr_proof: sp_mmr_primitives::Proof<H256>,
}

#[derive(sp_std::fmt::Debug, Clone, PartialEq, Eq, Encode, Decode)]
/// Parachain header definition
pub struct ParachainHeader {
	/// scale encoded parachain header
	pub parachain_header: Vec<u8>,
	/// Reconstructed mmr leaf
	pub partial_mmr_leaf: PartialMmrLeaf,
	/// parachain id
	pub para_id: u32,
	/// Proof for our parachain header inclusion in the parachain headers root
	pub parachain_heads_proof: Vec<Hash>,
	/// leaf index for parachain heads proof
	pub heads_leaf_index: u32,
	/// Total number of parachain heads
	pub heads_total_count: u32,
	/// Trie merkle proof of inclusion of the set timestamp extrinsic in header.extrinsic_root
	/// this already encodes the actual extrinsic
	pub extrinsic_proof: Vec<Vec<u8>>,
	/// Timestamp extrinsic
	pub timestamp_extrinsic: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct PartialMmrLeaf {
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

impl LightClient {
	/// Takes the updated client state and parachains headers update proof
	/// and verifies inclusion in mmr
	pub fn verify_parachain_headers(
		&self,
		ParachainsUpdateProof { mmr_proof, parachain_headers }: ParachainsUpdateProof,
	) -> Result<(), Error> {
		let mut mmr_leaves = Vec::new();

		for parachain_header in parachain_headers {
			let decoded_para_header = Header::decode(&mut &*parachain_header.parachain_header)
				.map_err(|e| Error::Custom(e.to_string()))?;

			// just to be safe skip genesis block if it's included, it has no timestamp
			if decoded_para_header.number == 0 {
				Err(Error::Custom("Genesis block found, it should not be included".to_string()))?
			}

			// Verify timestamp extrinsic
			// Timestamp extrinsic should be the first inherent and hence the first extrinsic
			// https://github.com/paritytech/substrate/blob/d602397a0bbb24b5d627795b797259a44a5e29e9/primitives/trie/src/lib.rs#L99-L101
			let timestamp_ext_key = codec::Compact(0u32).encode();
			sp_trie::verify_trie_proof::<sp_trie::LayoutV0<Keccak256>, _, _, _>(
				&H256::from(decoded_para_header.extrinsics_root),
				&&*parachain_header.extrinsic_proof,
				&vec![(timestamp_ext_key, Some(&*parachain_header.timestamp_extrinsic))],
			)
			.map_err(|_| Error::Custom("Invalid extrinsic proof".to_string()))?;

			let pair = (parachain_header.para_id, parachain_header.parachain_header);
			let leaf_bytes = pair.encode();

			let proof =
				rs_merkle::MerkleProof::<HashMerger>::new(parachain_header.parachain_heads_proof);
			let leaf_hash = Keccak256::hash(&leaf_bytes);
			let root = proof
				.root(
					&[parachain_header.heads_leaf_index as usize],
					&[leaf_hash.into()],
					parachain_header.heads_total_count as usize,
				)
				.map_err(|_| Error::Custom("Invalid Merkle Proof".to_string()))?;
			// reconstruct leaf
			let mmr_leaf = MmrLeaf {
				version: parachain_header.partial_mmr_leaf.version,
				parent_number_and_hash: parachain_header.partial_mmr_leaf.parent_number_and_hash,
				beefy_next_authority_set: parachain_header
					.partial_mmr_leaf
					.beefy_next_authority_set,
				leaf_extra: root.to_vec(),
			};

			let node: Hash = mmr_leaf.using_encoded(|leaf| Keccak256::hash(leaf)).into();
			let leaf_index = get_leaf_index_for_block_number(
				0,
				parachain_header.partial_mmr_leaf.parent_number_and_hash.0 + 1,
			);

			let leaf_pos = mmr_lib::leaf_index_to_pos(leaf_index as u64);
			mmr_leaves.push((leaf_pos, node));
		}

		let mmr_size = NodesUtils::new(mmr_proof.leaf_count).size();
		let proof = mmr_lib::MerkleProof::<Hash, HashMerger>::new(
			mmr_size,
			mmr_proof.items.clone().into_iter().map(|val| val.into()).collect(),
		);

		let root = proof.calculate_root(mmr_leaves).map_err(|e| Error::Custom(e.to_string()))?;
		let mmr_root_hash: [u8; 32] = self
			.latest_commitment
			.as_ref()
			.ok_or(Error::MissingLatestCommitment)?
			.payload
			.get_decoded(&MMR_ROOT_ID)
			.ok_or(Error::InvalidCommitmentPayload)?;
		if root != mmr_root_hash {
			return Err(Error::InvalidMmrProof(format!(
				"expected: {:?}, found: {:?}, location: {}",
				mmr_root_hash, root, "verify_parachain_headers"
			)))
		}
		Ok(())
	}
}

/// Calculate the leaf index for this block number
pub fn get_leaf_index_for_block_number(activation_block: u32, block_number: u32) -> u32 {
	// calculate the leaf index for this leaf.
	if activation_block == 0 {
		// in this case the leaf index is the same as the block number - 1 (leaf index starts at 0)
		block_number - 1
	} else {
		// in this case the leaf index is activation block - current block number.
		activation_block - (block_number + 1)
	}
}
