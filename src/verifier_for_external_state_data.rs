use crate::*;

pub trait BeefyKeySet {
	///
	fn contains(&self, sig: &Vec<u8>) -> bool;
	///
	fn len(&self) -> usize;
}

pub trait BeefyKeySetHistories<T: BeefyKeySet> {
	///
	fn get(&self, validator_set_id: u64) -> Option<T>;
}

///
pub fn verify_signed_commitment<T, S>(
	signed_commitment: &[u8],
	beefy_key_set_histories: &T,
	mmr_leaf: &[u8],
	mmr_proof: &[u8],
) -> Result<Commitment, Error>
where
	T: BeefyKeySetHistories<S>,
	S: BeefyKeySet,
{
	let signed_commitment = SignedCommitment::decode(&mut &signed_commitment[..])
		.map_err(|_| Error::InvalidSignedCommitment)?;

	let signatures_count = signed_commitment.signatures.iter().filter(|&sig| sig.is_some()).count();
	let SignedCommitment { commitment, signatures } = signed_commitment;

	let beefy_key_set = beefy_key_set_histories.get(commitment.validator_set_id);
	if beefy_key_set.is_none() {
		return Err(Error::MissingBeefyKeySetOfValidatorSet {
			validator_set_id: commitment.validator_set_id,
		})
	}
	let beefy_key_set = beefy_key_set.unwrap();

	if signatures_count < (beefy_key_set.len() / 2) as usize {
		return Err(Error::InvalidNumberOfSignatures {
			expected: (beefy_key_set.len() / 2) as usize,
			got: signatures_count,
		})
	}

	let commitment_hash = commitment.hash();
	verify_commitment_signatures(&commitment_hash, &signatures, &beefy_key_set)?;
	let mmr_root: [u8; 32] = commitment
		.payload
		.get_decoded(&MMR_ROOT_ID)
		.ok_or(Error::InvalidCommitmentPayload)?;
	let mmr_proof =
		mmr::MmrLeafProof::decode(&mut &mmr_proof[..]).map_err(|_| Error::CantDecodeMmrProof)?;
	let mmr_leaf: Vec<u8> =
		Decode::decode(&mut &mmr_leaf[..]).map_err(|_| Error::CantDecodeMmrLeaf)?;
	let mmr_leaf_hash = Keccak256::hash(&mmr_leaf[..]);
	let _mmr_leaf: MmrLeaf =
		Decode::decode(&mut &*mmr_leaf).map_err(|_| Error::CantDecodeMmrLeaf)?;
	let result = mmr::verify_leaf_proof(mmr_root, mmr_leaf_hash, mmr_proof)?;
	if !result {
		return Err(Error::InvalidMmrLeafProof)
	}

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

fn verify_commitment_signatures<T: BeefyKeySet>(
	commitment_hash: &Hash,
	signatures: &[Option<Signature>],
	beefy_key_set: &T,
) -> Result<(), Error> {
	let msg =
		libsecp256k1::Message::parse_slice(&commitment_hash[..]).or(Err(Error::InvalidMessage))?;
	for signature in signatures.iter().take(signatures.len()).flatten() {
		let sig = libsecp256k1::Signature::parse_standard_slice(&signature.0[..64])
			.or(Err(Error::InvalidSignature))?;
		let recovery_id =
			libsecp256k1::RecoveryId::parse(signature.0[64]).or(Err(Error::InvalidRecoveryId))?;
		let validator = libsecp256k1::recover(&msg, &sig, &recovery_id)
			.or(Err(Error::WrongSignature))?
			.serialize()
			.to_vec();
		if !beefy_key_set.contains(&validator) {
			return Err(Error::ValidatorNotFound)
		}
	}
	Ok(())
}
