use beefy_light_client::{
	beefy_ecdsa_to_ethereum,
	commitment::{Commitment, Signature, SignedCommitment},
	header::Header,
	mmr::{MmrLeaf, MmrLeafProof},
	new,
	validator_set::BeefyNextAuthoritySet,
	ValidatorMerkleProof,
};
use beefy_merkle_tree::{merkle_proof, merkle_root, Keccak256};
use codec::{Decode, Encode};
use hex_literal::hex;
use secp256k1_test::{rand::thread_rng, Message as SecpMessage, Secp256k1};

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

	let mut lc = new(public_keys);
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

	let encoded_signed_commitment_1 = hex!("f45927644a0b5bc6f1ce667330071fbaea498403c084eb0d4cb747114887345d0900000000000000000000001401b9b5b39fb15d7e22710ad06075cf0e20c4b0c1e3d0a6482946e1d0daf86ca2e37b40209316f00a549cdd2a7fd191694fee4f76f698d0525642563e665db85d6300010ee39cb2cb008f7dce753541b5442e98a260250286b335d6048f2dd4695237655ccc93ebcd3d7c04461e0b9d12b81b21a826c5ee3eebcd6ab9e85c8717f6b1ae010001b094279e0bb4442ba07165da47ab9c0d7d0f479e31d42c879564915714e8ea3d42393dc430addc4a5f416316c02e0676e525c56a3d0c0033224ebda4c83052670001f965d806a16c5dfb9d119f78cdbed379bccb071528679306208880ad29a9cf9e00e75f1b284fa3457b7b37223a2272cf2bf90ce4fd7e84e321eddec3cdeb66f801");
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

	let  encoded_mmr_leaf_1 = hex!("c501000800000079f0451c096266bee167393545bafc7b27b7d14810084a843955624588ba29c1010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_1[..]).unwrap();
	let mmr_leaf_1: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf_1: {:?}", mmr_leaf_1);

	let encoded_mmr_proof_1 =  hex!("0800000000000000090000000000000004c2d6348aef1ef52e779c59bcc1d87fa0175b59b4fa2ea8fc322e4ceb2bdd1ea2");
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

	let encoded_signed_commitment_2 = hex!("8d3cb96dca5110aff60423046bbf4a76db0e71158aa5586ffa3423fbaf9ef1da1100000000000000000000001401864ce4553324cc92db4ac622b9dbb031a6a4bd26ee1ab66e0272f567928865ec46847b55f98fa7e1dbafb0256f0a23e2f0a375e4547f5d1819d9b8694f17f6a80101c9ae8aad1b81e2249736324716c09c122889317e4f3e47066c501a839c15312e5c823dd37436d8e3bac8041329c5d0ed5dd94c45b5c1eed13d9111924f0a13c1000159fe06519c672d183de7776b6902a13c098d917721b5600a2296dca3a74a81bc01031a671fdb5e5050ff1f432d72e7a2c144ab38f8401ffd368e693257162a4600014290c6aa5028ceb3a3a773c80beee2821f3a7f5b43f592f7a82b0cbbbfab5ba41363daae5a7006fea2f89a30b4900f85fa82283587df789fd7b5b773ad7e8c410100");
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

	let encoded_mmr_leaf_2 = hex!("c5010010000000d0a3a930e5f3b0f997c3794023c86f8ba28c6ba2cacf230d08d46be0fdf29435010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_2[..]).unwrap();
	let mmr_leaf_2: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf_2: {:?}", mmr_leaf_2);

	let encoded_mmr_proof_2 = hex!("10000000000000001100000000000000048a766e1ab001e2ff796517dcfbff957a751c994aff4c3ba9447a46d88ec2ef15");
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

	let mut lc = new(public_keys);
	let commitment = Commitment {
		payload: hex!("7fe1460305e05d0937df34aa47a251811b0f83032fd153a64ebb8812cb252ee2"),
		block_number: 89,
		validator_set_id: 0,
	};
	lc.latest_commitment = Some(commitment);
	println!("light client: {:?}", lc);

	// Got cross-chain messages at block 81 with hash 0x63e59bf81115597c4fbd864998d610cda6bbe32c6e1319488f3eaa3c3ba5966e
	let messages = hex!("040100000000000000021000000000");
	let encoded_header = vec![
		10, 13, 22, 200, 67, 234, 70, 53, 53, 35, 181, 174, 39, 195, 107, 232, 128, 49, 144, 0, 46,
		49, 133, 110, 254, 85, 186, 83, 203, 199, 197, 6, 69, 1, 144, 163, 197, 173, 189, 82, 34,
		223, 212, 9, 231, 160, 19, 228, 191, 132, 66, 233, 82, 181, 164, 11, 244, 139, 67, 151,
		196, 198, 210, 20, 105, 63, 105, 3, 166, 96, 244, 224, 235, 128, 247, 251, 169, 168, 144,
		60, 51, 9, 243, 15, 221, 196, 212, 16, 234, 164, 29, 199, 205, 36, 112, 165, 9, 62, 20, 6,
		66, 65, 66, 69, 52, 2, 0, 0, 0, 0, 159, 96, 136, 32, 0, 0, 0, 0, 4, 66, 69, 69, 70, 132, 3,
		4, 27, 102, 51, 199, 84, 23, 10, 207, 202, 104, 184, 2, 235, 159, 61, 6, 10, 40, 223, 155,
		198, 15, 56, 24, 158, 249, 244, 126, 70, 119, 186, 4, 66, 65, 66, 69, 169, 3, 1, 20, 212,
		53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
		76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125, 1, 0, 0, 0, 0, 0, 0, 0, 142, 175, 4,
		21, 22, 135, 115, 99, 38, 201, 254, 161, 126, 37, 252, 82, 135, 97, 54, 147, 201, 18, 144,
		156, 178, 38, 170, 71, 148, 242, 106, 72, 1, 0, 0, 0, 0, 0, 0, 0, 144, 181, 171, 32, 92,
		105, 116, 201, 234, 132, 27, 230, 136, 134, 70, 51, 220, 156, 168, 163, 87, 132, 62, 234,
		207, 35, 20, 100, 153, 101, 254, 34, 1, 0, 0, 0, 0, 0, 0, 0, 48, 103, 33, 33, 29, 84, 4,
		189, 157, 168, 142, 2, 4, 54, 10, 26, 154, 184, 184, 124, 102, 193, 188, 47, 205, 211, 127,
		60, 34, 34, 204, 32, 1, 0, 0, 0, 0, 0, 0, 0, 230, 89, 167, 161, 98, 140, 221, 147, 254,
		188, 4, 164, 224, 100, 110, 162, 14, 159, 95, 12, 224, 151, 217, 160, 82, 144, 212, 169,
		224, 84, 223, 78, 1, 0, 0, 0, 0, 0, 0, 0, 37, 247, 211, 55, 231, 96, 163, 185, 188, 26,
		127, 33, 131, 57, 43, 42, 10, 32, 114, 255, 223, 190, 21, 179, 20, 120, 184, 196, 24, 104,
		65, 222, 0, 128, 99, 229, 155, 248, 17, 21, 89, 124, 79, 189, 134, 73, 152, 214, 16, 205,
		166, 187, 227, 44, 110, 19, 25, 72, 143, 62, 170, 60, 59, 165, 150, 110, 5, 66, 65, 66, 69,
		1, 1, 176, 82, 55, 247, 244, 160, 12, 115, 166, 169, 63, 233, 237, 9, 141, 45, 194, 186,
		67, 39, 32, 222, 11, 20, 122, 50, 3, 97, 121, 104, 223, 9, 80, 154, 189, 211, 112, 187,
		167, 113, 224, 8, 134, 78, 168, 215, 202, 1, 228, 214, 23, 143, 125, 11, 211, 149, 154,
		171, 25, 134, 44, 183, 166, 137,
	];

	let header: Header = Decode::decode(&mut &encoded_header[..]).unwrap();
	println!("header #81 {:?}", header);

	// Query mmr leaf with leaf index 81 (NOTE: not 81-1) at block 89
	// {
	//     blockHash: 0xd0d7c0b309926a2c64ed82f9a8ab8e2b037feb48fb3b783989bba30b041b1315
	//     leaf: 0xc5010051000000f728a8e3b29fb62b3234be2ba31e6beffd00bb571a978962ff9c26ea8dcc20ab010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000
	//     proof: 0x5100000000000000590000000000000018bddfdcc0399d0ce1be41f1126f63053ecb26ee19c107c0f96013f216b7b21933f8611a08a46cd74fd96d54d2eb19898dbd743b019bf7ba32b17b9a193f0e65b8c231bab606963f6a5a05071bea9af2a30f22adc43224affe87b3f90d1a07d0db4b6a7c61c56d1174067b6e816970631b8727f6dfe3ebd3923581472d45f47ad3940e1f16782fd635f4789d7f5674d2cbf12d1bbd7823c6ee37c807ad34424d48f0e3888f05a1d6183d9dbf8a91d3400ea2047b5e19d498968011e63b91058fbd
	// }

	let  encoded_mmr_leaf = hex!("c5010051000000f728a8e3b29fb62b3234be2ba31e6beffd00bb571a978962ff9c26ea8dcc20ab010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf[..]).unwrap();
	let mmr_leaf: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf: {:?}", mmr_leaf);

	let encoded_mmr_proof =  hex!("5100000000000000590000000000000018bddfdcc0399d0ce1be41f1126f63053ecb26ee19c107c0f96013f216b7b21933f8611a08a46cd74fd96d54d2eb19898dbd743b019bf7ba32b17b9a193f0e65b8c231bab606963f6a5a05071bea9af2a30f22adc43224affe87b3f90d1a07d0db4b6a7c61c56d1174067b6e816970631b8727f6dfe3ebd3923581472d45f47ad3940e1f16782fd635f4789d7f5674d2cbf12d1bbd7823c6ee37c807ad34424d48f0e3888f05a1d6183d9dbf8a91d3400ea2047b5e19d498968011e63b91058fbd");
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
	let commitment = Commitment {
		payload: hex!("f45927644a0b5bc6f1ce667330071fbaea498403c084eb0d4cb747114887345d"),
		block_number: 9,
		validator_set_id: 0,
	};
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

	let mut lc = new(vec!["0x00".to_string()]);
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
	let  encoded_mmr_leaf = hex!("c501000800000079f0451c096266bee167393545bafc7b27b7d14810084a843955624588ba29c1010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");
	let encoded_mmr_proof =  hex!("0800000000000000090000000000000004c2d6348aef1ef52e779c59bcc1d87fa0175b59b4fa2ea8fc322e4ceb2bdd1ea2");
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
	let commitment = Commitment {
		payload: hex!("f45927644a0b5bc6f1ce667330071fbaea498403c084eb0d4cb747114887345d"),
		block_number: 9,
		validator_set_id: 0,
	};
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

	let mut lc = new(vec!["0x00".to_string()]);
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
	let  encoded_mmr_leaf = hex!("c501000800000079f0451c096266bee167393545bafc7b27b7d14810084a843955624588ba29c1010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");
	let encoded_mmr_proof =  hex!("0800000000000000090000000000000004c2d6348aef1ef52e779c59bcc1d87fa0175b59b4fa2ea8fc322e4ceb2bdd1ea2");
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
