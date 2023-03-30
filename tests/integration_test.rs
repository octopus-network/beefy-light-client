use beefy_light_client::{
	beefy_ecdsa_to_ethereum,
	commitment::{Signature, SignedCommitment, VersionedFinalityProof},
	header::{Digest, Header},
	keccak256::Keccak256,
	mmr::{MmrLeaf, MmrLeavesProof},
	new,
	validator_set::BeefyNextAuthoritySet,
	ValidatorMerkleProof,
};
use binary_merkle_tree::{merkle_proof, merkle_root};
use codec::{Decode, Encode};
use hex_literal::hex;
use secp256k1_test::{rand::thread_rng, Message as SecpMessage, Secp256k1};
#[test]
#[ignore = "test failed"]
fn update_state_works() {
	// $ subkey inspect --scheme ecdsa //Alice
	// Secret Key URI `//Alice` is account:
	//   Public key (hex):  0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
	let public_keys = vec![
		"0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1", // Alice
		"0x0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27", // Bob
		"0x0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb", // Charlie
		"0x03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c", // Dave
	];

	let mut lc = new(public_keys.clone().into_iter().map(Into::into).collect());
	println!("light client: {:?}", lc);

	let leaves = public_keys
		.clone()
		.into_iter()
		.map(|leaf| beefy_ecdsa_to_ethereum(&hex::decode(leaf).unwrap()))
		.collect::<Vec<_>>();

	let validator_proofs_1 = (0..public_keys.len())
		.fold(vec![], |mut result, idx| {
			let merkle_proof: binary_merkle_tree::MerkleProof<beefy_light_client::Hash, Vec<u8>> =
				binary_merkle_tree::merkle_proof::<Keccak256, _, _>(leaves.clone(), idx);
			result.push(merkle_proof);
			result
		})
		.into_iter()
		.map(Into::into)
		.collect::<Vec<ValidatorMerkleProof>>();

	// 2023-03-30 16:59:58.228  INFO tokio-runtime-worker beefy: 🥩 Round #29 concluded, finality_proof:
	// V1(SignedCommitment { commitment: Commitment {
	// payload: Payload([([109, 104], [153, 241, 169, 211, 144, 135, 202, 236, 122, 173, 236, 72, 241, 110, 22, 172, 222, 151, 208, 222, 191, 14, 125, 221, 184, 167, 46, 100, 253, 11, 135, 221])]), block_number: 29, validator_set_id: 2 },
	// signatures: [Some(Signature(6379a51fad3831a60e661a90e3876ee625f6bb266231fcc6c77dfdf6cdcda16a1db027b937bf8f416c355986be9ff216182ad2034ffcfc280e63e29343b3404000)),
	// Some(Signature(0a1d4d4bf7603afaee8d98a0b77256c1e91691b2b614a1a72c41dc23e14d16cd203f77c4add4ce78ec4babd767e9afbf2993c67299929f5b2984012a9ef06e5000)),
	// None,
	// Some(Signature(af49836738db5b2ec0790db6c0d39bef62d3637372739dd49e3217350efcbad908cc6a7f5126c803d617607fa8178110e7645a9adcc4fcb2d069ec72fb8bbadd00))] }).

	let encoded_versioned_finality_proof_1 = hex!("01046d6880c217f03ad31ec31ce87868e09e5e495709f71afac633e76e8ef9b501324395d319000000000000000000000004b805000000105601084305efd41d12b85fb246c4d6a40ff23bd9d32cc795cef0c92193c334ec5d7316fdfd1bbec62afc65819f4afeb427bed5002109fefbce5176a2a87448fc0049fd387d312a512849fe068186f314f353a636c2ae7c4fdec3f077eac97439f25bbd21a6514b1f153f8e03e0aad662589c7ba8c24b05ec9e9b7a6d0f24d6a1610143b433d4bd8c9755766fe38a767a996d51ab78bd31ce37d4d494787383ce3797096018a4c28cd352281cfbc801893c5a0415b9bc430082afb772b3dab8de4ab50026908266e17631abaa9c9418432e129c2ff4fc4ef5f9ffa75b2b56d4f963a86528f2e99d9ad8ae2aacf30fd295b019600b3a055bf7ca1bbbea26823f421d25d601");
	let versioned_finality_proof_1 =
		VersionedFinalityProof::decode(&mut &encoded_versioned_finality_proof_1[..]);
	println!("versioned_finality_proof_1: {:?}", versioned_finality_proof_1);

	// get block hash of #25
	// {"id":216,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[25]}
	// {"jsonrpc":"2.0","result":"0xfed50296570e59a9ed78ef50fd1f7a8cefa8f549c8487de41205ad6f0f10fe4e","id":216}
	//
	// get leaf proof of index #24 at block #25
	// {"id":221,"jsonrpc":"2.0","method":"mmr_generateProof","params":[24,"0xfed50296570e59a9ed78ef50fd1f7a8cefa8f549c8487de41205ad6f0f10fe4e"]}
	// {"jsonrpc":"2.0","result":{"blockHash":"0xfed50296570e59a9ed78ef50fd1f7a8cefa8f549c8487de41205ad6f0f10fe4e","leaf":"0x49010018000000ca49d4211a41a1a807e5f3e101b638961bd13d29c29424bc70392a79ddd28883010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a200","proof":"0x1800000000000000190000000000000008aa39aef631e5db27573922ee5e00d6588acc586eb774954a0c0352e6221bd318a821d6b67d64cd6bef167ecf547fbca255d08202f287cd1abd63fa21e116abfc"},"id":221}
	let  encoded_mmr_leaf_1 = hex!("49010018000000ca49d4211a41a1a807e5f3e101b638961bd13d29c29424bc70392a79ddd28883010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a200");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_1[..]).unwrap();
	let mmr_leaf_1: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf_1: {:?}", mmr_leaf_1);

	let encoded_mmr_proof_1 =  hex!("1800000000000000190000000000000008aa39aef631e5db27573922ee5e00d6588acc586eb774954a0c0352e6221bd318a821d6b67d64cd6bef167ecf547fbca255d08202f287cd1abd63fa21e116abfc");
	let mmr_proof_1 = MmrLeavesProof::decode(&mut &encoded_mmr_proof_1[..]);
	println!("mmr_proof_1: {:?}", mmr_proof_1);
	assert!(lc
		.update_state(
			&encoded_versioned_finality_proof_1,
			&validator_proofs_1,
			&encoded_mmr_leaf_1,
			&encoded_mmr_proof_1,
		)
		.is_ok());
	println!("light client: {:?}", lc);

	// 2022-10-03 15:41:38 🥩 Round #33 concluded, finality_proof: V1(SignedCommitment { commitment: Commitment { payload: Payload([([109, 104], [89, 203, 81, 61, 201, 8, 173, 192, 75, 218, 141, 102, 24, 16, 0, 229, 194, 127, 78, 95, 3, 239, 246, 7, 204, 181, 168, 117, 120, 96, 128, 5])]), block_number: 33, validator_set_id: 0 }, signatures: [None, Some(Signature(c56be180c4efef50b220ddd47365db65031f01f72f88bd77864f281f9e290ecf0d99580fcd197d2137d06c6601fefff77f4532c11a3e7f6cfe334e902167b6fb00)), Some(Signature(d41d48f2af7bda217ee844c46d65dfc7075828051e1fb0dd873d2bdede25f22e30b1e5878282c2e500a646cff82eb93436db716b3025a4ace437d2bf79b00ac400)), Some(Signature(30153374e6d4cca8430d1c10ebdc58a0b66180b5a7ed1daca55de0bff09e7785534b6681a2410a82afa8ab02cad36928d2dd2f1162d542177f527204a8ce591c00)), Some(Signature(e6754323c95da8c584b4bb8216adec0f351fda339a50ae29031c623ed2db124875c7d75891de6450ff60ff8872c90fd9a5ba7cac4ebcc43a80f5ffe8062ba7e500))] }).
	let encoded_versioned_finality_proof_2 = hex!("01046d688059cb513dc908adc04bda8d66181000e5c27f4e5f03eff607ccb5a8757860800521000000000000000000000004b805000000109798d407632bb5c9078d8c442c5885ce20fb13b519092038335df7c3d913e3a7509836506f9aac28013bd45e197fd1adbb1843fb62957719ca499e7a499eac2900d41d48f2af7bda217ee844c46d65dfc7075828051e1fb0dd873d2bdede25f22e30b1e5878282c2e500a646cff82eb93436db716b3025a4ace437d2bf79b00ac40030153374e6d4cca8430d1c10ebdc58a0b66180b5a7ed1daca55de0bff09e7785534b6681a2410a82afa8ab02cad36928d2dd2f1162d542177f527204a8ce591c00e6754323c95da8c584b4bb8216adec0f351fda339a50ae29031c623ed2db124875c7d75891de6450ff60ff8872c90fd9a5ba7cac4ebcc43a80f5ffe8062ba7e500");
	let versioned_finality_proof_2 =
		VersionedFinalityProof::decode(&mut &encoded_versioned_finality_proof_2[..]);
	println!("versioned_finality_proof_2: {:?}", versioned_finality_proof_2);

	let validator_proofs_2 = (0..public_keys.len())
		.fold(vec![], |mut result, idx| {
			let merkle_proof: binary_merkle_tree::MerkleProof<beefy_light_client::Hash, Vec<u8>> =
				binary_merkle_tree::merkle_proof::<Keccak256, _, _>(leaves.clone(), idx);
			result.push(merkle_proof);
			result
		})
		.into_iter()
		.map(Into::into)
		.collect::<Vec<ValidatorMerkleProof>>();

	// get block hash of #33
	// {"id":195,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[33]}
	// {"jsonrpc":"2.0","result":"0xe436dae54995bc67662065bc3ed1dabd3657bd5e85080210e996f50755d625e1","id":195}
	//
	// get leaf proof of index #32 at block #33
	// {"id":236,"jsonrpc":"2.0","method":"mmr_generateProof","params":[32,"0xe436dae54995bc67662065bc3ed1dabd3657bd5e85080210e996f50755d625e1"]}
	// {"jsonrpc":"2.0","result":{"blockHash":"0xe436dae54995bc67662065bc3ed1dabd3657bd5e85080210e996f50755d625e1","leaf":"0x49010020000000f3f279b0f519eb692283622b1cc3d47dc437cff9e8d458f6f6583aa96649baca010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a200","proof":"0x20000000000000002100000000000000040a86dca09827c83d57156e813b37b3d781bafcaceba5edca1946975215641eb2"},"id":236}
	let encoded_mmr_leaf_2 = hex!("49010020000000f3f279b0f519eb692283622b1cc3d47dc437cff9e8d458f6f6583aa96649baca010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a200");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf_2[..]).unwrap();
	let mmr_leaf_2: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf_2: {:?}", mmr_leaf_2);

	let encoded_mmr_proof_2 = hex!("20000000000000002100000000000000040a86dca09827c83d57156e813b37b3d781bafcaceba5edca1946975215641eb2");
	let mmr_proof_2 = MmrLeavesProof::decode(&mut &encoded_mmr_proof_2[..]);
	println!("mmr_proof_2: {:?}", mmr_proof_2);
	assert!(lc
		.update_state(
			&encoded_versioned_finality_proof_2,
			&validator_proofs_2,
			&encoded_mmr_leaf_2,
			&encoded_mmr_proof_2,
		)
		.is_ok());
	println!("light client: {:?}", lc);
}

#[test]
#[ignore = "test failed"]
fn verify_solochain_messages_works() {
	let public_keys = vec![
		"0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1".to_string(), // Alice
		"0x0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27".to_string(), // Bob
		"0x0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb".to_string(), // Charlie
		"0x03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c".to_string(), // Dave
		"0x031d10105e323c4afce225208f71a6441ee327a65b9e646e772500c74d31f669aa".to_string(), // Eve
	];

	let mut lc = new(public_keys);

	// 2022-10-03 15:41:38 🥩 Round #33 concluded, finality_proof: V1(SignedCommitment { commitment: Commitment { payload: Payload([([109, 104], [89, 203, 81, 61, 201, 8, 173, 192, 75, 218, 141, 102, 24, 16, 0, 229, 194, 127, 78, 95, 3, 239, 246, 7, 204, 181, 168, 117, 120, 96, 128, 5])]), block_number: 33, validator_set_id: 0 }, signatures: [None, Some(Signature(c56be180c4efef50b220ddd47365db65031f01f72f88bd77864f281f9e290ecf0d99580fcd197d2137d06c6601fefff77f4532c11a3e7f6cfe334e902167b6fb00)), Some(Signature(d41d48f2af7bda217ee844c46d65dfc7075828051e1fb0dd873d2bdede25f22e30b1e5878282c2e500a646cff82eb93436db716b3025a4ace437d2bf79b00ac400)), Some(Signature(30153374e6d4cca8430d1c10ebdc58a0b66180b5a7ed1daca55de0bff09e7785534b6681a2410a82afa8ab02cad36928d2dd2f1162d542177f527204a8ce591c00)), Some(Signature(e6754323c95da8c584b4bb8216adec0f351fda339a50ae29031c623ed2db124875c7d75891de6450ff60ff8872c90fd9a5ba7cac4ebcc43a80f5ffe8062ba7e500))] }).
	let versioned_finality_proof = hex!("01046d688059cb513dc908adc04bda8d66181000e5c27f4e5f03eff607ccb5a8757860800521000000000000000000000004b805000000109798d407632bb5c9078d8c442c5885ce20fb13b519092038335df7c3d913e3a7509836506f9aac28013bd45e197fd1adbb1843fb62957719ca499e7a499eac2900d41d48f2af7bda217ee844c46d65dfc7075828051e1fb0dd873d2bdede25f22e30b1e5878282c2e500a646cff82eb93436db716b3025a4ace437d2bf79b00ac40030153374e6d4cca8430d1c10ebdc58a0b66180b5a7ed1daca55de0bff09e7785534b6681a2410a82afa8ab02cad36928d2dd2f1162d542177f527204a8ce591c00e6754323c95da8c584b4bb8216adec0f351fda339a50ae29031c623ed2db124875c7d75891de6450ff60ff8872c90fd9a5ba7cac4ebcc43a80f5ffe8062ba7e500");
	let VersionedFinalityProof::V1(signed_commitment) =
		VersionedFinalityProof::decode(&mut &versioned_finality_proof[..]).unwrap();
	lc.latest_commitment = Some(signed_commitment.commitment);
	println!("light client: {:?}", lc);

	// 2022-10-03 15:41:00.222 DEBUG tokio-runtime-worker runtime::octopus-upward-messages: [29] 🐙 commit cross-chain messages: hash: 0xc4bdaf856c6cfca2f8ce6a4fd6381b72bc6caf03f33f6d2602fc0e31690d46ea, key: [99, 111, 109, 109, 105, 116, 109, 101, 110, 116, 196, 189, 175, 133, 108, 108, 252, 162, 248, 206, 106, 79, 214, 56, 27, 114, 188, 108, 175, 3, 243, 63, 109, 38, 2, 252, 14, 49, 105, 13, 70, 234], messages: [Message { nonce: 1, payload_type: PayloadType::Lock, payload: [66, 0, 0, 0, 48, 120, 100, 52, 51, 53, 57, 51, 99, 55, 49, 53, 102, 100, 100, 51, 49, 99, 54, 49, 49, 52, 49, 97, 98, 100, 48, 52, 97, 57, 57, 102, 100, 54, 56, 50, 50, 99, 56, 53, 53, 56, 56, 53, 52, 99, 99, 100, 101, 51, 57, 97, 53, 54, 56, 52, 101, 55, 97, 53, 54, 100, 97, 50, 55, 100, 14, 0, 0, 0, 106, 117, 108, 105, 97, 110, 115, 117, 110, 46, 110, 101, 97, 114, 0, 0, 100, 167, 179, 182, 224, 13, 0, 0, 0, 0, 0, 0, 0, 0] }]
	//
	// Got cross-chain messages at block 29 with offchain storage key 0x636f6d6d69746d656e74c4bdaf856c6cfca2f8ce6a4fd6381b72bc6caf03f33f6d2602fc0e31690d46ea
	//
	// {"id":167,"jsonrpc":"2.0","method":"offchain_localStorageGet","params":["PERSISTENT","0x636f6d6d69746d656e74c4bdaf856c6cfca2f8ce6a4fd6381b72bc6caf03f33f6d2602fc0e31690d46ea"]}
	// {"jsonrpc":"2.0","result":"0x04010000000000000000a101420000003078643433353933633731356664643331633631313431616264303461393966643638323263383535383835346363646533396135363834653761353664613237640e0000006a756c69616e73756e2e6e656172000064a7b3b6e00d0000000000000000","id":167}
	let messages = hex!("04010000000000000000a101420000003078643433353933633731356664643331633631313431616264303461393966643638323263383535383835346363646533396135363834653761353664613237640e0000006a756c69616e73756e2e6e656172000064a7b3b6e00d0000000000000000");

	// {"id":173,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[29]}
	// {"jsonrpc":"2.0","result":"0xa0f351da7756719afb23d60f59ed8364f289050f72394f5ca6c557178e594bdd","id":173}
	//
	// {"id":178,"jsonrpc":"2.0","method":"chain_getHeader","params":["0xa0f351da7756719afb23d60f59ed8364f289050f72394f5ca6c557178e594bdd"]}
	// {"jsonrpc":"2.0","result":{"parentHash":"0xaf1dbf5877915673a52ded92627328eb405ea5535f8e8e4a0d11289f9c17fb2c","number":"0x1d","stateRoot":"0x79e4d81e201dbf5108b068d9af75419f2cf8df9f1771f018bd7e71271b212171","extrinsicsRoot":"0x7aecf3e03905fd945f4aa0a04d2baa7d879efc0206ae7ebd4296e65768c36825","digest":{"logs":["0x064241424534020400000002c3891000000000","0x0080c4bdaf856c6cfca2f8ce6a4fd6381b72bc6caf03f33f6d2602fc0e31690d46ea","0x044245454684032033570c5c16d54546ec9c8d4e59b910b966ddad4f039be0b005a2f6bebe6c4c","0x0542414245010168e56176997bd6db5b30ac082b0ee6ddffc1d33cb9484542514f52f6ccb966104c15d9d3af8377bf436aec02224228782350b04303e8b1d733b1c3535efc1283"]}},"id":178}
	let item0 = hex!("064241424534020400000002c3891000000000");
	let item1 = hex!("0080c4bdaf856c6cfca2f8ce6a4fd6381b72bc6caf03f33f6d2602fc0e31690d46ea");
	let item2 =
		hex!("044245454684032033570c5c16d54546ec9c8d4e59b910b966ddad4f039be0b005a2f6bebe6c4c");
	let item3 = hex!("0542414245010168e56176997bd6db5b30ac082b0ee6ddffc1d33cb9484542514f52f6ccb966104c15d9d3af8377bf436aec02224228782350b04303e8b1d733b1c3535efc1283");
	let header = Header {
		parent_hash: hex!("af1dbf5877915673a52ded92627328eb405ea5535f8e8e4a0d11289f9c17fb2c"),
		number: 0x1d,
		state_root: hex!("79e4d81e201dbf5108b068d9af75419f2cf8df9f1771f018bd7e71271b212171"),
		extrinsics_root: hex!("7aecf3e03905fd945f4aa0a04d2baa7d879efc0206ae7ebd4296e65768c36825"),
		digest: Digest {
			logs: vec![
				Decode::decode(&mut &item0[..]).unwrap(),
				Decode::decode(&mut &item1[..]).unwrap(),
				Decode::decode(&mut &item2[..]).unwrap(),
				Decode::decode(&mut &item3[..]).unwrap(),
			],
		},
	};

	println!("block hash #29: {:?}", header.hash());
	println!("header #29 {:?}", header);
	let encoded_header = header.encode();

	// {"id":195,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[33]}
	// {"jsonrpc":"2.0","result":"0xe436dae54995bc67662065bc3ed1dabd3657bd5e85080210e996f50755d625e1","id":195}
	// Query mmr leaf with leaf index 29 (NOTE: not 29-1) at block 33
	// {"id":200,"jsonrpc":"2.0","method":"mmr_generateProof","params":[29,"0xe436dae54995bc67662065bc3ed1dabd3657bd5e85080210e996f50755d625e1"]}
	// {"jsonrpc":"2.0","result":{"blockHash":"0xe436dae54995bc67662065bc3ed1dabd3657bd5e85080210e996f50755d625e1","leaf":"0x4901001d000000a0f351da7756719afb23d60f59ed8364f289050f72394f5ca6c557178e594bdd010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a200","proof":"0x1d000000000000002100000000000000189ab2308aee9171fab99e59bc86ade273bb249e8e287543ee077798de8416155427524b23d1c1f1d0d17fc1c523b6e03e7def2724ed17057a31ef235157d30f1d7f70e28c4e02e65ca5dae450bba580fbf5c991b95dfe6a6d58246e2895d72233a821d6b67d64cd6bef167ecf547fbca255d08202f287cd1abd63fa21e116abfcaa39aef631e5db27573922ee5e00d6588acc586eb774954a0c0352e6221bd3183b099e7b31e66b8b9bb220b79f21d56b27bd0b4d524ad5f4cc85bc9f1c49aa57"},"id":200}

	let encoded_mmr_leaf = hex!("4901001d000000a0f351da7756719afb23d60f59ed8364f289050f72394f5ca6c557178e594bdd010000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a200");

	let leaf: Vec<u8> = Decode::decode(&mut &encoded_mmr_leaf[..]).unwrap();
	let mmr_leaf: MmrLeaf = Decode::decode(&mut &*leaf).unwrap();
	println!("mmr_leaf: {:?}", mmr_leaf);

	let encoded_mmr_proof =  hex!("1d000000000000002100000000000000189ab2308aee9171fab99e59bc86ade273bb249e8e287543ee077798de8416155427524b23d1c1f1d0d17fc1c523b6e03e7def2724ed17057a31ef235157d30f1d7f70e28c4e02e65ca5dae450bba580fbf5c991b95dfe6a6d58246e2895d72233a821d6b67d64cd6bef167ecf547fbca255d08202f287cd1abd63fa21e116abfcaa39aef631e5db27573922ee5e00d6588acc586eb774954a0c0352e6221bd3183b099e7b31e66b8b9bb220b79f21d56b27bd0b4d524ad5f4cc85bc9f1c49aa57");
	let mmr_proof = MmrLeavesProof::decode(&mut &encoded_mmr_proof[..]);
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
	// 2023-03-30 17:49:10.084  INFO tokio-runtime-worker beefy: 🥩 Round #521 concluded, finality_proof:
	// V1(SignedCommitment { commitment: Commitment {
	// payload: Payload([([109, 104], [150, 43, 35, 254, 104, 148, 7, 222, 197, 200, 134, 148, 51, 102, 183, 103, 116, 191, 174, 69, 142, 30, 62, 195, 117, 200, 189, 35, 166, 135, 209, 229])]),
	//block_number: 521, validator_set_id: 52 },
	// signatures: [Some(Signature(05e12fd2077a8e29261eb3eb5ed84530de19e685f90077834dd7e77c210e09331bafca18252cfe18e32bd0d9f73edaececd66c12dc85a9c1d270eb9aeccf0c6901)),
	// Some(Signature(dd53eee478ed535e9607e616e3facfad83299e34bdd33ff373ee4244a27675d7326721bbb758ca7f558a5e8de089f35377c76da26f60707bff496115e3f113c100)),
	// Some(Signature(76aacf8006e4e736493e771ba34fa2a37189af9f995a6cd4dbd1874503860bdf7b2a8b9709a53a13a950001f03395540f6b8c8157ca4407b5eed7cc76b9ba0e501)),
	// None] }).
	let versioned_finality_proof =
		VersionedFinalityProof::V1(beefy_light_client::commitment::SignedCommitment {
			commitment: beefy_light_client::commitment::Commitment {
				payload: beefy_light_client::commitment::Payload::new(
					[109, 104],
					vec![
						150, 43, 35, 254, 104, 148, 7, 222, 197, 200, 134, 148, 51, 102, 183, 103,
						116, 191, 174, 69, 142, 30, 62, 195, 117, 200, 189, 35, 166, 135, 209, 229,
					],
				),
				block_number: 521,
				validator_set_id: 52,
			},
			signatures: vec![Some(beefy_light_client::commitment::Signature(hex!("05e12fd2077a8e29261eb3eb5ed84530de19e685f90077834dd7e77c210e09331bafca18252cfe18e32bd0d9f73edaececd66c12dc85a9c1d270eb9aeccf0c6901"))), Some(beefy_light_client::commitment::Signature(hex!("dd53eee478ed535e9607e616e3facfad83299e34bdd33ff373ee4244a27675d7326721bbb758ca7f558a5e8de089f35377c76da26f60707bff496115e3f113c100"))), Some(beefy_light_client::commitment::Signature(hex!("76aacf8006e4e736493e771ba34fa2a37189af9f995a6cd4dbd1874503860bdf7b2a8b9709a53a13a950001f03395540f6b8c8157ca4407b5eed7cc76b9ba0e501"))), None],
		}).encode();
	let VersionedFinalityProof::V1(signed_commitment) =
		VersionedFinalityProof::decode(&mut &versioned_finality_proof[..]).unwrap();
	let commitment_hash = signed_commitment.commitment.hash();
	let msg = SecpMessage::from_slice(&commitment_hash[..]).unwrap();
	// re-sign this commit for testing
	let mut signed_commitment =
		SignedCommitment { commitment: signed_commitment.commitment, signatures: vec![] };

	for _ in 0..MAX_VALIDATORS {
		let (privkey, pubkey) = secp.generate_keypair(&mut thread_rng());
		let validator_address = beefy_ecdsa_to_ethereum(&pubkey.serialize());
		initial_public_keys.push(validator_address);
		let (recover_id, signature) =
			secp.sign_ecdsa_recoverable(&msg, &privkey).serialize_compact();

		let mut buf = [0_u8; 65];
		buf[0..64].copy_from_slice(&signature[..]);
		buf[64] = recover_id.to_i32() as u8;

		signed_commitment.signatures.push(Some(Signature(buf)));
	}
	let encoded_versioned_finality_proof = VersionedFinalityProof::V1(signed_commitment).encode();

	let mut lc = new(vec!["0x00".to_string()]);
	lc.validator_set = BeefyNextAuthoritySet {
		id: 0,
		len: initial_public_keys.len() as u32,
		root: merkle_root::<Keccak256, _>(initial_public_keys.clone()),
	};
	let mut validator_proofs = Vec::new();
	for i in 0..initial_public_keys.len() {
		let proof = merkle_proof::<Keccak256, _, _>(initial_public_keys.clone(), i);
		validator_proofs.push(ValidatorMerkleProof {
			root: proof.root,
			proof: proof.proof.clone(),
			number_of_leaves: proof.number_of_leaves,
			leaf_index: proof.leaf_index,
			leaf: proof.leaf,
		});
	}

	println!("lc: {:?}", lc);
	// block number is 520, best block number is 521
	// {
	// blockHash: 0x520956d0f5bd45f35389beb6cf0715b0974557fff875cf442fe6f7bb6ff093e7
	// leaves: 0x04c5010007020000bb0576987ab832eb81270b9cf567ebcde78dba4504676708d35e60be5f5b15303400000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe290565190000000000000000000000000000000000000000000000000000000000000000
	// proof: 0x040702000000000000090200000000000014d6e36dcd294eb0a1cc41681d4099c8d5a86c7e831ff5ab949cc61e3364f23f9c5a8cdfd47b6a12623572d9fae49aa39f520a59f2ebf1df0b7110626ae0193e125267be700432ad675caa3816556dd678db0bd5d94d071407fd1b4afdb08b6ccf5415f233cd7c365b20294b165d08b63e283a473dd66891d39ff07ce79d9ea6032575091d45688203aeb228875814282946bd27b107eb810751f0d05c14c096e0
	// }
	let encoded_mmr_leaf = hex!("04c5010007020000bb0576987ab832eb81270b9cf567ebcde78dba4504676708d35e60be5f5b15303400000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe290565190000000000000000000000000000000000000000000000000000000000000000");
	let encoded_mmr_proof = hex!("040702000000000000090200000000000014d6e36dcd294eb0a1cc41681d4099c8d5a86c7e831ff5ab949cc61e3364f23f9c5a8cdfd47b6a12623572d9fae49aa39f520a59f2ebf1df0b7110626ae0193e125267be700432ad675caa3816556dd678db0bd5d94d071407fd1b4afdb08b6ccf5415f233cd7c365b20294b165d08b63e283a473dd66891d39ff07ce79d9ea6032575091d45688203aeb228875814282946bd27b107eb810751f0d05c14c096e0");
	assert!(lc
		.update_state(
			&encoded_versioned_finality_proof,
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
	// 2023-03-30 17:49:10.084  INFO tokio-runtime-worker beefy: 🥩 Round #521 concluded, finality_proof:
	// V1(SignedCommitment { commitment: Commitment {
	// payload: Payload([([109, 104], [150, 43, 35, 254, 104, 148, 7, 222, 197, 200, 134, 148, 51, 102, 183, 103, 116, 191, 174, 69, 142, 30, 62, 195, 117, 200, 189, 35, 166, 135, 209, 229])]),
	//block_number: 521, validator_set_id: 52 },
	// signatures: [Some(Signature(05e12fd2077a8e29261eb3eb5ed84530de19e685f90077834dd7e77c210e09331bafca18252cfe18e32bd0d9f73edaececd66c12dc85a9c1d270eb9aeccf0c6901)),
	// Some(Signature(dd53eee478ed535e9607e616e3facfad83299e34bdd33ff373ee4244a27675d7326721bbb758ca7f558a5e8de089f35377c76da26f60707bff496115e3f113c100)),
	// Some(Signature(76aacf8006e4e736493e771ba34fa2a37189af9f995a6cd4dbd1874503860bdf7b2a8b9709a53a13a950001f03395540f6b8c8157ca4407b5eed7cc76b9ba0e501)),
	// None] }).
	let versioned_finality_proof =
		VersionedFinalityProof::V1(beefy_light_client::commitment::SignedCommitment {
			commitment: beefy_light_client::commitment::Commitment {
				payload: beefy_light_client::commitment::Payload::new(
					[109, 104],
					vec![
						150, 43, 35, 254, 104, 148, 7, 222, 197, 200, 134, 148, 51, 102, 183, 103,
						116, 191, 174, 69, 142, 30, 62, 195, 117, 200, 189, 35, 166, 135, 209, 229,
					],
				),
				block_number: 521,
				validator_set_id: 52,
			},
			signatures: vec![Some(beefy_light_client::commitment::Signature(hex!("05e12fd2077a8e29261eb3eb5ed84530de19e685f90077834dd7e77c210e09331bafca18252cfe18e32bd0d9f73edaececd66c12dc85a9c1d270eb9aeccf0c6901"))), Some(beefy_light_client::commitment::Signature(hex!("dd53eee478ed535e9607e616e3facfad83299e34bdd33ff373ee4244a27675d7326721bbb758ca7f558a5e8de089f35377c76da26f60707bff496115e3f113c100"))), Some(beefy_light_client::commitment::Signature(hex!("76aacf8006e4e736493e771ba34fa2a37189af9f995a6cd4dbd1874503860bdf7b2a8b9709a53a13a950001f03395540f6b8c8157ca4407b5eed7cc76b9ba0e501"))), None],
		}).encode();

	let VersionedFinalityProof::V1(signed_commitment) =
		VersionedFinalityProof::decode(&mut &versioned_finality_proof[..]).unwrap();
	let commitment_hash = signed_commitment.commitment.hash();
	let msg = SecpMessage::from_slice(&commitment_hash[..]).unwrap();
	let mut signed_commitment =
		SignedCommitment { commitment: signed_commitment.commitment, signatures: vec![] };

	for _ in 0..MAX_VALIDATORS {
		let (privkey, pubkey) = secp.generate_keypair(&mut thread_rng());
		let validator_address = beefy_ecdsa_to_ethereum(&pubkey.serialize());
		initial_public_keys.push(validator_address);
		let (recover_id, signature) =
			secp.sign_ecdsa_recoverable(&msg, &privkey).serialize_compact();

		let mut buf = [0_u8; 65];
		buf[0..64].copy_from_slice(&signature[..]);
		buf[64] = recover_id.to_i32() as u8;

		signed_commitment.signatures.push(Some(Signature(buf)));
	}
	let encoded_versioned_finality_proof = VersionedFinalityProof::V1(signed_commitment).encode();

	let mut lc = new(vec!["0x00".to_string()]);
	lc.validator_set = BeefyNextAuthoritySet {
		id: 0,
		len: initial_public_keys.len() as u32,
		root: merkle_root::<Keccak256, _>(initial_public_keys.clone()),
	};
	let mut validator_proofs = Vec::new();
	for i in 0..initial_public_keys.len() {
		let proof = merkle_proof::<Keccak256, _, _>(initial_public_keys.clone(), i);
		validator_proofs.push(ValidatorMerkleProof {
			root: proof.root,
			proof: proof.proof.clone(),
			number_of_leaves: proof.number_of_leaves,
			leaf_index: proof.leaf_index,
			leaf: proof.leaf,
		});
	}

	println!("lc: {:?}", lc);
	// block number is 520, best block number is 521
	// {
	// blockHash: 0x520956d0f5bd45f35389beb6cf0715b0974557fff875cf442fe6f7bb6ff093e7
	// leaves: 0x04c5010007020000bb0576987ab832eb81270b9cf567ebcde78dba4504676708d35e60be5f5b15303400000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe290565190000000000000000000000000000000000000000000000000000000000000000
	// proof: 0x040702000000000000090200000000000014d6e36dcd294eb0a1cc41681d4099c8d5a86c7e831ff5ab949cc61e3364f23f9c5a8cdfd47b6a12623572d9fae49aa39f520a59f2ebf1df0b7110626ae0193e125267be700432ad675caa3816556dd678db0bd5d94d071407fd1b4afdb08b6ccf5415f233cd7c365b20294b165d08b63e283a473dd66891d39ff07ce79d9ea6032575091d45688203aeb228875814282946bd27b107eb810751f0d05c14c096e0
	// }
	let encoded_mmr_leaf = hex!("04c5010007020000bb0576987ab832eb81270b9cf567ebcde78dba4504676708d35e60be5f5b15303400000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe290565190000000000000000000000000000000000000000000000000000000000000000");
	let encoded_mmr_proof = hex!("040702000000000000090200000000000014d6e36dcd294eb0a1cc41681d4099c8d5a86c7e831ff5ab949cc61e3364f23f9c5a8cdfd47b6a12623572d9fae49aa39f520a59f2ebf1df0b7110626ae0193e125267be700432ad675caa3816556dd678db0bd5d94d071407fd1b4afdb08b6ccf5415f233cd7c365b20294b165d08b63e283a473dd66891d39ff07ce79d9ea6032575091d45688203aeb228875814282946bd27b107eb810751f0d05c14c096e0");
	assert!(lc
		.start_updating_state(
			&encoded_versioned_finality_proof,
			&validator_proofs,
			&encoded_mmr_leaf,
			&encoded_mmr_proof,
		)
		.is_ok());
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
