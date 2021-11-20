use beefy_light_client::{
	beefy_ecdsa_to_ethereum,
	commitment::{Commitment, SignedCommitment},
	header::Header,
	mmr::{MmrLeaf, MmrLeafProof},
	new, MerkleProof,
};
use codec::Decode;
use hex_literal::hex;

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
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("f68aec7304bf37f340dae2ea20fb5271ee28a3128812b84a615da4789e458bde").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 0,
			leaf: alice_pk.clone(),
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 1,
			leaf: bob_pk.clone(),
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("50bdd3ac4f54a04702a055c33303025b2038446c7334ed3b3341f310f052116f").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 2,
			leaf: charlie_pk.clone(),
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("3eb799651607280e854bd2e42c1df1c8e4a6167772dfb3c64a813e40f6e87136").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 3,
			leaf: dave_pk.clone(),
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
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
			validator_proofs_1,
			&encoded_mmr_leaf_1,
			&encoded_mmr_proof_1,
		)
		.is_ok());
	println!("light client: {:?}", lc);

	let encoded_signed_commitment_2 = hex!("8d3cb96dca5110aff60423046bbf4a76db0e71158aa5586ffa3423fbaf9ef1da1100000000000000000000001401864ce4553324cc92db4ac622b9dbb031a6a4bd26ee1ab66e0272f567928865ec46847b55f98fa7e1dbafb0256f0a23e2f0a375e4547f5d1819d9b8694f17f6a80101c9ae8aad1b81e2249736324716c09c122889317e4f3e47066c501a839c15312e5c823dd37436d8e3bac8041329c5d0ed5dd94c45b5c1eed13d9111924f0a13c1000159fe06519c672d183de7776b6902a13c098d917721b5600a2296dca3a74a81bc01031a671fdb5e5050ff1f432d72e7a2c144ab38f8401ffd368e693257162a4600014290c6aa5028ceb3a3a773c80beee2821f3a7f5b43f592f7a82b0cbbbfab5ba41363daae5a7006fea2f89a30b4900f85fa82283587df789fd7b5b773ad7e8c410100");
	let signed_commitment_2 = SignedCommitment::decode(&mut &encoded_signed_commitment_2[..]);
	println!("signed_commitment_2: {:?}", signed_commitment_2);

	let validator_proofs_2 = vec![
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("f68aec7304bf37f340dae2ea20fb5271ee28a3128812b84a615da4789e458bde").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 0,
			leaf: alice_pk,
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7").into(),
				hex!("93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 1,
			leaf: bob_pk,
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("50bdd3ac4f54a04702a055c33303025b2038446c7334ed3b3341f310f052116f").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 2,
			leaf: charlie_pk,
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("3eb799651607280e854bd2e42c1df1c8e4a6167772dfb3c64a813e40f6e87136").into(),
				hex!("697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402").into(),
				hex!("55ca68207e72b7a7cd012364e03ac9ee560eb1b26de63f0ee42a649d74f3bf58").into(),
			],
			number_of_leaves: 5,
			leaf_index: 3,
			leaf: dave_pk,
		},
		MerkleProof {
			root: hex!("304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2").into(),
			proof: vec![
				hex!("2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519").into()
			],
			number_of_leaves: 5,
			leaf_index: 4,
			leaf: eve_pk,
		},
	];

	let  encoded_mmr_leaf_2 = hex!("c5010010000000d0a3a930e5f3b0f997c3794023c86f8ba28c6ba2cacf230d08d46be0fdf29435010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_2[..]).unwrap();
	let mmr_leaf_2: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf_2: {:?}", mmr_leaf_2);

	let encoded_mmr_proof_2 =  hex!("10000000000000001100000000000000048a766e1ab001e2ff796517dcfbff957a751c994aff4c3ba9447a46d88ec2ef15");
	let mmr_proof_2 = MmrLeafProof::decode(&mut &encoded_mmr_proof_2[..]);
	println!("mmr_proof_2: {:?}", mmr_proof_2);
	assert!(lc
		.update_state(
			&encoded_signed_commitment_2,
			validator_proofs_2,
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
		payload: hex!("7256c3f5a07409714e446d24fb7ea72a3f8e9f6503777aa47823fc6bad40cd96"),
		block_number: 89,
		validator_set_id: 0,
	};
	lc.latest_commitment = Some(commitment);
	println!("light client: {:?}", lc);

	// Got cross-chain messages at block 81 with commit hash 0x812570086a0f983665ea15b992352c338e89dcb83454e670ee5108e3142f302b
	let messages = vec![4, 1, 0, 0, 0, 0, 0, 0, 0, 2, 16, 0, 0, 0, 0];
	let encoded_header = vec![
		188, 249, 19, 41, 129, 143, 64, 158, 14, 184, 194, 196, 222, 154, 109, 232, 133, 70, 155,
		213, 59, 71, 201, 74, 47, 194, 63, 178, 118, 39, 85, 237, 69, 1, 50, 209, 105, 73, 130, 76,
		114, 241, 117, 30, 203, 118, 48, 18, 30, 229, 151, 145, 247, 205, 19, 208, 173, 60, 106,
		208, 80, 95, 194, 91, 78, 126, 112, 130, 79, 102, 95, 70, 212, 160, 134, 113, 57, 119, 54,
		84, 218, 108, 167, 9, 21, 41, 127, 84, 241, 43, 18, 142, 140, 213, 176, 48, 178, 3, 20, 6,
		66, 65, 66, 69, 52, 2, 4, 0, 0, 0, 249, 44, 136, 32, 0, 0, 0, 0, 4, 66, 69, 69, 70, 132, 3,
		175, 227, 250, 51, 109, 132, 249, 145, 216, 101, 22, 66, 71, 205, 70, 163, 135, 15, 63,
		119, 240, 183, 32, 90, 106, 150, 151, 247, 76, 190, 171, 94, 4, 66, 65, 66, 69, 169, 3, 1,
		20, 212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133,
		88, 133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125, 1, 0, 0, 0, 0, 0, 0, 0, 142,
		175, 4, 21, 22, 135, 115, 99, 38, 201, 254, 161, 126, 37, 252, 82, 135, 97, 54, 147, 201,
		18, 144, 156, 178, 38, 170, 71, 148, 242, 106, 72, 1, 0, 0, 0, 0, 0, 0, 0, 144, 181, 171,
		32, 92, 105, 116, 201, 234, 132, 27, 230, 136, 134, 70, 51, 220, 156, 168, 163, 87, 132,
		62, 234, 207, 35, 20, 100, 153, 101, 254, 34, 1, 0, 0, 0, 0, 0, 0, 0, 48, 103, 33, 33, 29,
		84, 4, 189, 157, 168, 142, 2, 4, 54, 10, 26, 154, 184, 184, 124, 102, 193, 188, 47, 205,
		211, 127, 60, 34, 34, 204, 32, 1, 0, 0, 0, 0, 0, 0, 0, 230, 89, 167, 161, 98, 140, 221,
		147, 254, 188, 4, 164, 224, 100, 110, 162, 14, 159, 95, 12, 224, 151, 217, 160, 82, 144,
		212, 169, 224, 84, 223, 78, 1, 0, 0, 0, 0, 0, 0, 0, 37, 247, 211, 55, 231, 96, 163, 185,
		188, 26, 127, 33, 131, 57, 43, 42, 10, 32, 114, 255, 223, 190, 21, 179, 20, 120, 184, 196,
		24, 104, 65, 222, 0, 128, 129, 37, 112, 8, 106, 15, 152, 54, 101, 234, 21, 185, 146, 53,
		44, 51, 142, 137, 220, 184, 52, 84, 230, 112, 238, 81, 8, 227, 20, 47, 48, 43, 5, 66, 65,
		66, 69, 1, 1, 0, 121, 128, 255, 122, 229, 201, 17, 26, 66, 3, 120, 221, 146, 13, 229, 181,
		25, 167, 79, 20, 137, 203, 194, 250, 218, 34, 56, 144, 198, 186, 91, 141, 246, 64, 130,
		154, 48, 11, 17, 118, 213, 57, 234, 138, 223, 220, 209, 125, 20, 10, 101, 162, 229, 201,
		246, 78, 64, 167, 154, 3, 132, 252, 141,
	];

	let header: Header = Decode::decode(&mut &encoded_header[..]).unwrap();
	println!("header #81 {:?}", header);

	// Query mmr leaf with leaf index 81-1 at block 89
	// {
	//     blockHash: 0x9b06cf8492be40bebbd27dcbf63cde5d4fe1e91494e56d6e66455e5e97c8bcb8
	//     leaf: 0xc5010050000000bcf91329818f409e0eb8c2c4de9a6de885469bd53b47c94a2fc23fb2762755ed010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000
	//     proof: 0x5000000000000000590000000000000018b30435845b8ffb6a85e7c8fb90addd2867f42b7e719bb6af05fa0ba7ffa184fbd59cc9dd6365ac18de4ca734fb1e411b265fae16cd88d9bdda618c7780b3962cc3131bc2d3184851b54f1d653276c129ad2fe9dccfc58af547d41332666902c2d7e14274ae442781c7114edead993544757003c8fc0d024d8c500ebe3b7f8a15e739d459e3f94386d09ee002e092288f7dc8649b1e7f8d5727489d0286b5ad1bc4fa016c5e80dfba7d2a3b479d73a4b203289d4c250939582a33406cae0de368
	// }

	// Query mmr leaf with leaf index 81 at block 89
	// {
	//     blockHash: 0x9b06cf8492be40bebbd27dcbf63cde5d4fe1e91494e56d6e66455e5e97c8bcb8
	//     leaf: 0xc50100510000003340b448372fd1fe54f07ad142b2e828da79ad6ddb7c94cffcdd5d0c0aa65103010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000
	//     proof: 0x5100000000000000590000000000000018b30435845b8ffb6a85e7c8fb90addd2867f42b7e719bb6af05fa0ba7ffa184fbd59cc9dd6365ac18de4ca734fb1e411b265fae16cd88d9bdda618c7780b3962c5478542315554efa31adce73f3c6bb3db282b7c573ee7a47c62755e50a9e7307d7e14274ae442781c7114edead993544757003c8fc0d024d8c500ebe3b7f8a15e739d459e3f94386d09ee002e092288f7dc8649b1e7f8d5727489d0286b5ad1bc4fa016c5e80dfba7d2a3b479d73a4b203289d4c250939582a33406cae0de368
	// }

	let  encoded_mmr_leaf = hex!("c50100510000003340b448372fd1fe54f07ad142b2e828da79ad6ddb7c94cffcdd5d0c0aa65103010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf[..]).unwrap();
	let mmr_leaf: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf: {:?}", mmr_leaf);

	let encoded_mmr_proof =  hex!("5100000000000000590000000000000018b30435845b8ffb6a85e7c8fb90addd2867f42b7e719bb6af05fa0ba7ffa184fbd59cc9dd6365ac18de4ca734fb1e411b265fae16cd88d9bdda618c7780b3962c5478542315554efa31adce73f3c6bb3db282b7c573ee7a47c62755e50a9e7307d7e14274ae442781c7114edead993544757003c8fc0d024d8c500ebe3b7f8a15e739d459e3f94386d09ee002e092288f7dc8649b1e7f8d5727489d0286b5ad1bc4fa016c5e80dfba7d2a3b479d73a4b203289d4c250939582a33406cae0de368");
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
