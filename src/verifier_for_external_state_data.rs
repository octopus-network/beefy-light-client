use crate::*;

pub trait LightClientStateData {
	///
	fn contains_authority_set(&self, set_id: &ValidatorSetId) -> bool;
	///
	fn get_authority_set(&self, set_id: &ValidatorSetId) -> Option<BeefyNextAuthoritySet>;
	///
	fn store_authority_set(&mut self, validator_set: &BeefyNextAuthoritySet);
	///
	fn contains_commitment(&self, commitment: &Commitment) -> bool;
	///
	fn get_commitment(
		&self,
		block_number: &u32,
		validator_set_id: &ValidatorSetId,
	) -> Option<Commitment>;
	///
	fn store_commitment(&mut self, commitment: &Commitment);
}

///
pub fn verify_signed_commitment<T: LightClientStateData>(
	signed_commitment: &[u8],
	validator_proofs: &[ValidatorMerkleProof],
	mmr_leaf: &[u8],
	mmr_proof: &[u8],
	light_client_state_data: &mut T,
) -> Result<Commitment, Error> {
	let signed_commitment = SignedCommitment::decode(&mut &signed_commitment[..])
		.map_err(|_| Error::InvalidSignedCommitment)?;
	let SignedCommitment { commitment, signatures } = signed_commitment;

	if light_client_state_data.contains_commitment(&commitment) {
		return Ok(commitment)
	}

	let validator_set = match light_client_state_data
		.get_authority_set(&commitment.validator_set_id)
	{
		Some(validator_set) => validator_set,
		None => match light_client_state_data.get_authority_set(&(commitment.validator_set_id - 1))
		{
			Some(validator_set) => validator_set,
			None =>
				return Err(Error::MissingBeefyAuthoritySetOf {
					validator_set_id: commitment.validator_set_id,
				}),
		},
	};

	let signatures_count = signatures.iter().filter(|&sig| sig.is_some()).count();
	if signatures_count < (validator_set.len / 2) as usize {
		return Err(Error::InvalidNumberOfSignatures {
			expected: (validator_set.len / 2) as usize,
			got: signatures_count,
		})
	}

	let commitment_hash = commitment.hash();
	LightClient::verify_commitment_signatures(
		&commitment_hash,
		&signatures,
		&validator_set.root,
		validator_proofs,
		0,
		signatures.len(),
	)?;
	let mmr_root: [u8; 32] = commitment
		.payload
		.get_decoded(&MMR_ROOT_ID)
		.ok_or(Error::InvalidCommitmentPayload)?;
	let mmr_proof =
		mmr::MmrLeafProof::decode(&mut &mmr_proof[..]).map_err(|_| Error::CantDecodeMmrProof)?;
	let mmr_leaf: Vec<u8> =
		Decode::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
	let mmr_leaf_hash = Keccak256::hash(&mmr_leaf[..]);
	let mmr_leaf: MmrLeaf =
		Decode::decode(&mut &*mmr_leaf).map_err(|_| Error::CantDecodeMmrLeaf)?;
	let result = mmr::verify_leaf_proof(mmr_root, mmr_leaf_hash, mmr_proof)?;
	if !result {
		return Err(Error::InvalidMmrLeafProof)
	}

	light_client_state_data.store_commitment(&commitment);
	light_client_state_data.store_authority_set(&mmr_leaf.beefy_next_authority_set);

	Ok(commitment)
}

///
pub fn verify_solochain_messages(
	messages: &[u8],
	header: &[u8],
	commitment: &Commitment,
	mmr_leaf: &[u8],
	mmr_proof: &[u8],
) -> Result<(), Error> {
	let header = Header::decode(&mut &header[..]).map_err(|_| Error::CantDecodeHeader)?;
	let header_digest = header.get_other().ok_or(Error::DigestNotFound)?;

	let messages_hash = Keccak256::hash(messages);
	if messages_hash != header_digest[..] {
		return Err(Error::DigestNotMatch)
	}

	let mmr_root: [u8; 32] = commitment
		.payload
		.get_decoded(&MMR_ROOT_ID)
		.ok_or(Error::InvalidCommitmentPayload)?;
	let mmr_proof =
		mmr::MmrLeafProof::decode(&mut &mmr_proof[..]).map_err(|_| Error::CantDecodeMmrProof)?;
	let mmr_leaf: Vec<u8> =
		Decode::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
	let mmr_leaf_hash = Keccak256::hash(&mmr_leaf[..]);
	let mmr_leaf: MmrLeaf =
		Decode::decode(&mut &*mmr_leaf).map_err(|_| Error::CantDecodeMmrLeaf)?;

	let header_hash = header.hash();
	if header_hash != mmr_leaf.parent_number_and_hash.1 {
		return Err(Error::HeaderHashNotMatch)
	}

	let result = mmr::verify_leaf_proof(mmr_root, mmr_leaf_hash, mmr_proof)?;
	if !result {
		return Err(Error::InvalidMmrLeafProof)
	}
	Ok(())
}

///
pub fn calculate_merkle_root_of(public_keys: Vec<String>) -> Hash {
	let public_keys: Vec<Vec<u8>> = public_keys
		.into_iter()
		.map(|hex_str| {
			hex::decode(&hex_str[2..])
				.map(|compressed_key| beefy_ecdsa_to_ethereum(&compressed_key))
				.unwrap_or_default()
		})
		.collect();
	merkle_root::<Keccak256, _, _>(public_keys)
}
