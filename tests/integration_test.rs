use beefy_light_client::{
	beefy_ecdsa_to_ethereum,
	commitment::{
		known_payload_ids::MMR_ROOT_ID, Commitment, Payload, Signature, SignedCommitment,
	},
	header::{Digest, Header},
	mmr::{MmrLeaf, MmrLeafProof},
	validator_set::BeefyNextAuthoritySet,
	LightClient, ValidatorMerkleProof,
};
use beefy_merkle_tree::{merkle_proof, merkle_root, Keccak256};
use codec::{Decode, Encode};
use hex_literal::hex;
use secp256k1_test::{rand::thread_rng, Message as SecpMessage, Secp256k1};
use std::convert::TryInto;

#[test]
fn update_state_works() {
	// $ subkey inspect --scheme ecdsa //Alice
	// Secret Key URI `//Alice` is account:
	//   Public key (hex):  0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
	let public_keys = vec![
		"0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1".to_string(), // Alice
		"0x0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27".to_string(), // Bob
		"0x0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb".to_string(), // Charlie
		"0x03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c".to_string(), // Dave
		"0x031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa".to_string(), // Eve
	];

	let mut lc = LightClient::new(public_keys);
	println!("light client: {:?}", lc);

	let alice_pk = beefy_ecdsa_to_ethereum(
		&hex!("020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1")[..],
	);
	let bob_pk = beefy_ecdsa_to_ethereum(
		&hex!("0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27")[..],
	);
	let charlie_pk = beefy_ecdsa_to_ethereum(
		&hex!("0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb")[..],
	);
	let dave_pk = beefy_ecdsa_to_ethereum(
		&hex!("03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c")[..],
	);
	let eve_pk = beefy_ecdsa_to_ethereum(
		&hex!("031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa")[..],
	);

	let encoded_signed_commitment_1 = hex!("046d688017ffed791fa51b459d3c953a1f8f3e4718bcf8aa571a19bc0327d82761d3257909000000000000000000000004d80500000010c73029d26bba5d549db469b75950c4cb55aaf43de0044a32612acca99445bbf93a1edbc9f5fa5151c1a2e2b6f59968eb1485d001c6b9078c2ed310bad20779b001a4b79f6018e3936a64bd3281dca522fb33bf68720afff458c7ca0db1bfbd270d36c5c3db98abb59d9abbeda7b74b83510120172e7aa6c74f5c9239c85befa85f003bed8b85ff2f466df62569d4cd0169773b4ae4dde1139d4d0721b497f938312803e1885b21f6230ef5a8e44ad3dbbb1cd0e89226a41e35507e91ed62bcf4dc22013f45d94e3a6b97f5208d90d2bf3f2702a440f3f453c438cdd553bf2f2cc02cc23b230b3b12c1e68e39fbaf701e65457a372facba3c530ab56f3eec5e6766eddb01");
	let signed_commitment_1 = SignedCommitment::decode(&mut &encoded_signed_commitment_1[..]);
	println!("signed_commitment_1: {:?}", signed_commitment_1);

	let validator_proofs_1 = vec![
		ValidatorMerkleProof {
			proof: vec![
				hex!("f68aec7304bf37f340dae2ea20fb5271ee28a3128812b84a615da4789e458bde").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 0,
			leaf: alice_pk.clone(),
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 1,
			leaf: bob_pk.clone(),
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("50bdd3ac4f54a04702a055c33303025b2038446c7334ed3b3341f310f052116f").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 2,
			leaf: charlie_pk.clone(),
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("3eb799651607280e854bd2e42c1df1c8e4a6167772dfb3c64a813e40f6e87136").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 3,
			leaf: dave_pk.clone(),
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519").into()
			],
			number_of_leaves: 5,
			leaf_index: 4,
			leaf: eve_pk.clone(),
		},
	];

	let  encoded_mmr_leaf_1 = hex!("c50100080000005717d626ed925ebf1deaf25cb24ad7bca9384bbe533a938856466cc09fd26292010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_1[..]).unwrap();
	let mmr_leaf_1: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf_1: {:?}", mmr_leaf_1);

	let encoded_mmr_proof_1 =  hex!("0800000000000000090000000000000004effbabd0a9fcade34208684b3d5d69a52b2c9bc9265d872c2590636acd6342a0");
	let mmr_proof_1 = MmrLeafProof::decode(&mut &encoded_mmr_proof_1[..]);
	println!("mmr_proof_1: {:?}", mmr_proof_1);
	assert!(lc
		.update_state(
			&encoded_signed_commitment_1,
			&validator_proofs_1,
			&encoded_mmr_leaf_1,
			&encoded_mmr_proof_1,
		)
		.is_ok());
	println!("light client: {:?}", lc);

	let encoded_signed_commitment_2 = hex!("046d688037d21b14f9701ca2deb9946dbad32de48d8df3ad8988bfaabdbafa329fe07ccd11000000000000000000000004d80500000010b6f60090f011f376a7673d38a810ad15423381fbf6e8e1a88c2d39d58b5473b83dae3750c39be39be17bada861944b2d6f43c7e329b247905eb17dc3ecdb7f8a0062969c39737b7b3101d639ed2bd8aa3a61647bb4569d2a6c78b450e46012879919c90b149493d523d030490e389b3d4ee1e3f2a24f4e0cf5cd4944c03921ed3500389cf1cfe7c117052416db37920594387170fd404f79b98dc39f9b56ede6865a10306bf55a2d8814e36dbb51142f015813acbb1b187fdfefcc1f05b6505dce83019962e14afb83630dffec978b47f52016af699d21d4b1661acf4c01bb4845adcc4fa3e421dca35fb0c4d58d387bdc0d11ec161502e7c6f85c86849f569bc8b4c401");
	let signed_commitment_2 = SignedCommitment::decode(&mut &encoded_signed_commitment_2[..]);
	println!("signed_commitment_2: {:?}", signed_commitment_2);

	let validator_proofs_2 = vec![
		ValidatorMerkleProof {
			proof: vec![
				hex!("f68aec7304bf37f340dae2ea20fb5271ee28a3128812b84a615da4789e458bde").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 0,
			leaf: alice_pk,
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 1,
			leaf: bob_pk,
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("50bdd3ac4f54a04702a055c33303025b2038446c7334ed3b3341f310f052116f").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 2,
			leaf: charlie_pk,
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("3eb799651607280e854bd2e42c1df1c8e4a6167772dfb3c64a813e40f6e87136").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 3,
			leaf: dave_pk,
		},
		ValidatorMerkleProof {
			proof: vec![
				hex!("2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519").into()
			],
			number_of_leaves: 5,
			leaf_index: 4,
			leaf: eve_pk,
		},
	];

	let encoded_mmr_leaf_2 = hex!("c501001000000027aa6e9a63fe73429eaadc49018eed6d2f6362cdb18744677acfaca8be94838a010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_2[..]).unwrap();
	let mmr_leaf_2: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf_2: {:?}", mmr_leaf_2);

	let encoded_mmr_proof_2 = hex!("10000000000000001100000000000000043b96661a7161a6a760af588ebdefc79401e1c046d889d59f76d824406f713188");
	let mmr_proof_2 = MmrLeafProof::decode(&mut &encoded_mmr_proof_2[..]);
	println!("mmr_proof_2: {:?}", mmr_proof_2);
	assert!(lc
		.update_state(
			&encoded_signed_commitment_2,
			&validator_proofs_2,
			&encoded_mmr_leaf_2,
			&encoded_mmr_proof_2,
		)
		.is_ok());
	println!("light client: {:?}", lc);
}

#[test]
fn verify_solochain_messages_works() {
	let public_keys = vec![
		"0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1".to_string(), // Alice
		"0x0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27".to_string(), // Bob
		"0x0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb".to_string(), // Charlie
		"0x03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c".to_string(), // Dave
		"0x031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa".to_string(), // Eve
	];

	let mut lc = LightClient::new(public_keys);
	let payload = Payload::new(
		MMR_ROOT_ID,
		hex!("67678b4a811dc055ff865fdfdda11c7464a9c77a988af4fcdea92e38ae6c6320").to_vec(),
	);
	let commitment = Commitment { payload, block_number: 25, validator_set_id: 0 };
	lc.latest_commitment = Some(commitment);
	println!("light client: {:?}", lc);

	// Got cross-chain messages at block 22 with hash 0xe961cf2536958785869a8f1892c478ff5f91c5a01ece8a50d7f52cc5d31f96d3
	let messages = hex!("04010000000000000000a90142000000307864343335393363373135666464333163363131343161626430346139396664363832326338353538383534636364653339613536383465376135366461323764100000007975616e6368616f2e746573746e6574000004cfc542fd380200000000000000");

	// {"id":100,"jsonrpc":"2.0","method":"chain_getHeader","params":["0xe961cf2536958785869a8f1892c478ff5f91c5a01ece8a50d7f52cc5d31f96d3"]}
	// {"jsonrpc":"2.0","result":{"digest":{"logs":["0x06424142453402040000000abc701000000000","0x0080d8ac54c560a613a6df1ac3822c72d24999499916e3edad338cd4339d6c05489f","0x044245454684031f33ca534a85015f13b1221bd63077cde02615c0dcda544f252058e500541d7d","0x0542414245010104e71e466d9268304f634093921c4c3af3f25d3ea83b21c023e2269b6ce8b92e6f944a906e584e73e3aafc74b23efdf0dc25e63ca45b57b347abfaa0c06f6781"]},"extrinsicsRoot":"0x58d6476afb15a09ca68b12ea9521cad576688ead5b9078732c1e863a93708070","number":"0x16","parentHash":"0xf00dc4fb3ffe5e87359f159b344e78b94ef0b02554cf4d620f0b763d99f9aada","stateRoot":"0x56bf9703deec2388fcc336898b2f278a7a3cf9ea5cfb753b3015440cb12ac76f"},"id":100}
	let item0 = hex!("06424142453402040000000abc701000000000");
	let item1 = hex!("0080d8ac54c560a613a6df1ac3822c72d24999499916e3edad338cd4339d6c05489f");
	let item2 =
		hex!("044245454684031f33ca534a85015f13b1221bd63077cde02615c0dcda544f252058e500541d7d");
	let item3 = hex!("0542414245010104e71e466d9268304f634093921c4c3af3f25d3ea83b21c023e2269b6ce8b92e6f944a906e584e73e3aafc74b23efdf0dc25e63ca45b57b347abfaa0c06f6781");
	let header = Header {
		parent_hash: hex!("f00dc4fb3ffe5e87359f159b344e78b94ef0b02554cf4d620f0b763d99f9aada")
			.try_into()
			.unwrap(),
		number: 0x16,
		state_root: hex!("56bf9703deec2388fcc336898b2f278a7a3cf9ea5cfb753b3015440cb12ac76f")
			.try_into()
			.unwrap(),
		extrinsics_root: hex!("58d6476afb15a09ca68b12ea9521cad576688ead5b9078732c1e863a93708070")
			.try_into()
			.unwrap(),
		digest: Digest {
			logs: vec![
				Decode::decode(&mut &item0[..]).unwrap(),
				Decode::decode(&mut &item1[..]).unwrap(),
				Decode::decode(&mut &item2[..]).unwrap(),
				Decode::decode(&mut &item3[..]).unwrap(),
			],
		},
	};

	println!("block hash #22: {:?}", header.hash());
	println!("header #22 {:?}", header);
	let encoded_header = header.encode();

	// Query mmr leaf with leaf index 22 (NOTE: not 22-1) at block 25
	// {"id":237,"jsonrpc":"2.0","method":"mmr_generateProof","params":[22,"0x9e1ef7817c0b5e1196324e6cdb3fcfc583ad4cf5fdf163bf40cf1b5094a8fec5"]}
	// {"jsonrpc":"2.0","result":{
	// "blockHash":"0x9e1ef7817c0b5e1196324e6cdb3fcfc583ad4cf5fdf163bf40cf1b5094a8fec5",
	// "leaf":"0xc5010016000000e961cf2536958785869a8f1892c478ff5f91c5a01ece8a50d7f52cc5d31f96d3010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000",
	// "proof":"0x16000000000000001900000000000000143b96661a7161a6a760af588ebdefc79401e1c046d889d59f76d824406f713188c58385673dc5fffca2611dec971872597fa18462ec82f781d44c7f51f888460a927066f988d8d2b5c193a0fca08920bc21c56dfd2ea44fdcd9ceb97acd22e1a5dc8d1b12b23542b45f9e025bc4e611129aae70a08a7180839c8b698becf48e2326479d9be91711c950d8584e9f9dd49b6424e13d590afc8b00a41d5be40c4fb5"},
	// "id":237}

	let encoded_mmr_leaf = hex!("c5010016000000e961cf2536958785869a8f1892c478ff5f91c5a01ece8a50d7f52cc5d31f96d3010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf[..]).unwrap();
	let mmr_leaf: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf: {:?}", mmr_leaf);

	let encoded_mmr_proof =  hex!("16000000000000001900000000000000143b96661a7161a6a760af588ebdefc79401e1c046d889d59f76d824406f713188c58385673dc5fffca2611dec971872597fa18462ec82f781d44c7f51f888460a927066f988d8d2b5c193a0fca08920bc21c56dfd2ea44fdcd9ceb97acd22e1a5dc8d1b12b23542b45f9e025bc4e611129aae70a08a7180839c8b698becf48e2326479d9be91711c950d8584e9f9dd49b6424e13d590afc8b00a41d5be40c4fb5");
	let mmr_proof = MmrLeafProof::decode(&mut &encoded_mmr_proof[..]);
	println!("mmr_proof: {:?}", mmr_proof);

	assert!(lc
		.verify_solochain_messages(
			&messages,
			&encoded_header,
			&encoded_mmr_leaf,
			&encoded_mmr_proof,
		)
		.is_ok());
}

#[test]
fn maximum_validators_test() {
	const MAX_VALIDATORS: i32 = 100;

	let secp = Secp256k1::new();

	let mut initial_public_keys = Vec::new();
	let payload = Payload::new(
		MMR_ROOT_ID,
		hex!("67678b4a811dc055ff865fdfdda11c7464a9c77a988af4fcdea92e38ae6c6320").to_vec(),
	);
	let commitment = Commitment { payload, block_number: 25, validator_set_id: 0 };
	let commitment_hash = commitment.hash();
	let msg = SecpMessage::from_slice(&commitment_hash[..]).unwrap();
	let mut signed_commitment = SignedCommitment { commitment, signatures: vec![] };

	for _ in 0..MAX_VALIDATORS {
		let (privkey, pubkey) = secp.generate_keypair(&mut thread_rng());
		// println!("pubkey: {:?}", pubkey);
		// println!("prikey: {:?}", privkey);
		let validator_address = beefy_ecdsa_to_ethereum(&pubkey.serialize());
		// println!("validator_address: {:?}", validator_address);
		initial_public_keys.push(validator_address);
		let (recover_id, signature) = secp.sign_recoverable(&msg, &privkey).serialize_compact();

		let mut buf = [0_u8; 65];
		buf[0..64].copy_from_slice(&signature[..]);
		buf[64] = recover_id.to_i32() as u8;

		signed_commitment.signatures.push(Some(Signature(buf)));
	}
	let encoded_signed_commitment = signed_commitment.encode();

	let mut lc = LightClient::new(vec!["0x00".to_string()]);
	lc.validator_set = BeefyNextAuthoritySet {
		id: 0,
		len: initial_public_keys.len() as u32,
		root: merkle_root::<Keccak256, _, _>(initial_public_keys.clone()),
	};
	let mut validator_proofs = Vec::new();
	for i in 0..initial_public_keys.len() {
		let proof = merkle_proof::<Keccak256, _, _>(initial_public_keys.clone(), i);
		validator_proofs.push(ValidatorMerkleProof {
			proof: proof.proof.clone(),
			number_of_leaves: proof.number_of_leaves,
			leaf_index: proof.leaf_index,
			leaf: proof.leaf,
		});
	}

	println!("lc: {:?}", lc);
	let encoded_mmr_leaf = hex!("c5010016000000e961cf2536958785869a8f1892c478ff5f91c5a01ece8a50d7f52cc5d31f96d3010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");
	let encoded_mmr_proof = hex!("16000000000000001900000000000000143b96661a7161a6a760af588ebdefc79401e1c046d889d59f76d824406f713188c58385673dc5fffca2611dec971872597fa18462ec82f781d44c7f51f888460a927066f988d8d2b5c193a0fca08920bc21c56dfd2ea44fdcd9ceb97acd22e1a5dc8d1b12b23542b45f9e025bc4e611129aae70a08a7180839c8b698becf48e2326479d9be91711c950d8584e9f9dd49b6424e13d590afc8b00a41d5be40c4fb5");
	assert!(lc
		.update_state(
			&encoded_signed_commitment,
			&validator_proofs,
			&encoded_mmr_leaf,
			&encoded_mmr_proof,
		)
		.is_ok());
	println!("lc: {:?}", lc);
}

#[test]
fn update_state_in_multiple_steps() {
	const MAX_VALIDATORS: i32 = 100;

	let secp = Secp256k1::new();

	let mut initial_public_keys = Vec::new();
	let payload = Payload::new(
		MMR_ROOT_ID,
		hex!("67678b4a811dc055ff865fdfdda11c7464a9c77a988af4fcdea92e38ae6c6320").to_vec(),
	);
	let commitment = Commitment { payload, block_number: 25, validator_set_id: 0 };
	let commitment_hash = commitment.hash();
	let msg = SecpMessage::from_slice(&commitment_hash[..]).unwrap();
	let mut signed_commitment = SignedCommitment { commitment, signatures: vec![] };

	for _ in 0..MAX_VALIDATORS {
		let (privkey, pubkey) = secp.generate_keypair(&mut thread_rng());
		// println!("pubkey: {:?}", pubkey);
		// println!("prikey: {:?}", privkey);
		let validator_address = beefy_ecdsa_to_ethereum(&pubkey.serialize());
		// println!("validator_address: {:?}", validator_address);
		initial_public_keys.push(validator_address);
		let (recover_id, signature) = secp.sign_recoverable(&msg, &privkey).serialize_compact();

		let mut buf = [0_u8; 65];
		buf[0..64].copy_from_slice(&signature[..]);
		buf[64] = recover_id.to_i32() as u8;

		signed_commitment.signatures.push(Some(Signature(buf)));
	}
	let encoded_signed_commitment = signed_commitment.encode();

	let mut lc = LightClient::new(vec!["0x00".to_string()]);
	lc.validator_set = BeefyNextAuthoritySet {
		id: 0,
		len: initial_public_keys.len() as u32,
		root: merkle_root::<Keccak256, _, _>(initial_public_keys.clone()),
	};
	let mut validator_proofs = Vec::new();
	for i in 0..initial_public_keys.len() {
		let proof = merkle_proof::<Keccak256, _, _>(initial_public_keys.clone(), i);
		validator_proofs.push(ValidatorMerkleProof {
			proof: proof.proof.clone(),
			number_of_leaves: proof.number_of_leaves,
			leaf_index: proof.leaf_index,
			leaf: proof.leaf,
		});
	}

	println!("lc: {:?}", lc);
	let encoded_mmr_leaf = hex!("c5010016000000e961cf2536958785869a8f1892c478ff5f91c5a01ece8a50d7f52cc5d31f96d3010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");
	let encoded_mmr_proof =  hex!("16000000000000001900000000000000143b96661a7161a6a760af588ebdefc79401e1c046d889d59f76d824406f713188c58385673dc5fffca2611dec971872597fa18462ec82f781d44c7f51f888460a927066f988d8d2b5c193a0fca08920bc21c56dfd2ea44fdcd9ceb97acd22e1a5dc8d1b12b23542b45f9e025bc4e611129aae70a08a7180839c8b698becf48e2326479d9be91711c950d8584e9f9dd49b6424e13d590afc8b00a41d5be40c4fb5");
	assert!(lc
		.start_updating_state(
			&encoded_signed_commitment,
			&validator_proofs,
			&encoded_mmr_leaf,
			&encoded_mmr_proof,
		)
		.is_ok());
	// println!("lc: {:?}", lc);
	loop {
		if let Some(ref in_process_state) = lc.in_process_state {
			println!("position: {:?}", in_process_state.position);
		}
		let result = lc.complete_updating_state(9);
		assert!(result.is_ok());
		if result == Ok(true) {
			break
		}
	}
	println!("lc: {:?}", lc);
}
