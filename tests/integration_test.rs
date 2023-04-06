use beefy_light_client::{
	beefy_ecdsa_to_ethereum,
	commitment::{Signature, SignedCommitment, VersionedFinalityProof},
	keccak256::Keccak256,
	validator_set::BeefyNextAuthoritySet,
	LightClient, ValidatorMerkleProof,
};
use binary_merkle_tree::{merkle_proof, merkle_root};
use codec::{Decode, Encode};
use hex_literal::hex;
use secp256k1_test::{rand::thread_rng, Message as SecpMessage, Secp256k1};

#[test]
fn update_state_works() {
	// $ subkey inspect --scheme ecdsa //Alice
	// Secret Key URI `//Alice` is account:
	//   Public key (hex):  0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1
	let public_keys = vec![
		"020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1".to_string(), // Alice
		"0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27".to_string(), // Bob
		"0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb".to_string(), // Charlie
		"03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c".to_string(), // Dave
	];

	// authoritySetRoot: {"id":0,"len":4,"root":"0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519"}
	// authoritySetProof: {"root":"0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519","proof":["0xf68aec7304bf37f340dae2ea20fb5271ee28a3128812b84a615da4789e458bde","0x93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab"],"number_of_leaves":4,"leaf_index":0,"leaf":"0xe04cc55ebee1cbce552f250e85c57b70b2e2625b"}
	// authoritySetProof: {"root":"0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519","proof":["0xaeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7","0x93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab"],"number_of_leaves":4,"leaf_index":1,"leaf":"0x25451a4de12dccc2d166922fa938e900fcc4ed24"}
	// authoritySetProof: {"root":"0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519","proof":["0x50bdd3ac4f54a04702a055c33303025b2038446c7334ed3b3341f310f052116f","0x697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402"],"number_of_leaves":4,"leaf_index":2,"leaf":"0x5630a480727cd7799073b36472d9b1a6031f840b"}
	// authoritySetProof: {"root":"0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519","proof":["0x3eb799651607280e854bd2e42c1df1c8e4a6167772dfb3c64a813e40f6e87136","0x697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce402"],"number_of_leaves":4,"leaf_index":3,"leaf":"0x4bb32a4263e369acbb6c020ffa89a41fd9722894"}
	// encoded authoritySetProof: 0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651908f68aec7304bf37f340dae2ea20fb5271ee28a3128812b84a615da4789e458bde93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab0400000000000000000000000000000050e04cc55ebee1cbce552f250e85c57b70b2e2625b
	// encoded authoritySetProof: 0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651908aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d793c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab040000000000000001000000000000005025451a4de12dccc2d166922fa938e900fcc4ed24
	// encoded authoritySetProof: 0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe290565190850bdd3ac4f54a04702a055c33303025b2038446c7334ed3b3341f310f052116f697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce40204000000000000000200000000000000505630a480727cd7799073b36472d9b1a6031f840b
	// encoded authoritySetProof: 0x2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519083eb799651607280e854bd2e42c1df1c8e4a6167772dfb3c64a813e40f6e87136697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce40204000000000000000300000000000000504bb32a4263e369acbb6c020ffa89a41fd9722894
	let encoded_authority_set_proof = vec![
        hex!("2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651908f68aec7304bf37f340dae2ea20fb5271ee28a3128812b84a615da4789e458bde93c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab0400000000000000000000000000000050e04cc55ebee1cbce552f250e85c57b70b2e2625b").to_vec(),
        hex!("2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651908aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d793c6c7e160154c8467b700c291a1d4da94ae9aaf1c5010003a6aa3e9b18657ab040000000000000001000000000000005025451a4de12dccc2d166922fa938e900fcc4ed24").to_vec(),
        hex!("2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe290565190850bdd3ac4f54a04702a055c33303025b2038446c7334ed3b3341f310f052116f697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce40204000000000000000200000000000000505630a480727cd7799073b36472d9b1a6031f840b").to_vec(),
        hex!("2145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe29056519083eb799651607280e854bd2e42c1df1c8e4a6167772dfb3c64a813e40f6e87136697ea2a8fe5b03468548a7a413424a6292ab44a82a6f5cc594c3fa7dda7ce40204000000000000000300000000000000504bb32a4263e369acbb6c020ffa89a41fd9722894").to_vec(),
    ];

	let mut lc = LightClient::new(public_keys);

	// versionedFinalityProof: {"version":1,"commitment":{"payload":[["0x6d68","0x6562967f2108e09124f0f41c8fac19d34f3e66e4fe174010a70dc7b3013cc867"]],"blockNumber":17,"validatorSetId":0},"signatures_from":"0xb0","validator_set_len":4,"signatures_compact":["0xdea8a73e4536c824d1c4a250e1814847394d4af12c953a8f8e38f6c9aba4346054610f638bc0b96097e3f5fb621db2bc394e90d8a941db7cb4513c36b99a4b5001","0x474b736813aca2532f90bdb3af15a05a5c6acb5443f70b7d93d50be9dec1c6d277447bdbbc4383a7318f19c4f9a976c05fbf04c55787f2f8acea7a352d6a3a3b01","0x4d5030229be0084ee3b11e386bde84ecf7f78f31ca88e399c09fa09488821aee52836c147a920b9c891c2b65fe1c6b3ac4a6ca70bbdb66e88ff105804ab0c4ba00"]}
	// encoded versionedFinalityProof: 0x01046d68806562967f2108e09124f0f41c8fac19d34f3e66e4fe174010a70dc7b3013cc86711000000000000000000000004b0040000000cdea8a73e4536c824d1c4a250e1814847394d4af12c953a8f8e38f6c9aba4346054610f638bc0b96097e3f5fb621db2bc394e90d8a941db7cb4513c36b99a4b5001474b736813aca2532f90bdb3af15a05a5c6acb5443f70b7d93d50be9dec1c6d277447bdbbc4383a7318f19c4f9a976c05fbf04c55787f2f8acea7a352d6a3a3b014d5030229be0084ee3b11e386bde84ecf7f78f31ca88e399c09fa09488821aee52836c147a920b9c891c2b65fe1c6b3ac4a6ca70bbdb66e88ff105804ab0c4ba00
	let encoded_versioned_finality_proof_1 = hex!("01046d68806562967f2108e09124f0f41c8fac19d34f3e66e4fe174010a70dc7b3013cc86711000000000000000000000004b0040000000cdea8a73e4536c824d1c4a250e1814847394d4af12c953a8f8e38f6c9aba4346054610f638bc0b96097e3f5fb621db2bc394e90d8a941db7cb4513c36b99a4b5001474b736813aca2532f90bdb3af15a05a5c6acb5443f70b7d93d50be9dec1c6d277447bdbbc4383a7318f19c4f9a976c05fbf04c55787f2f8acea7a352d6a3a3b014d5030229be0084ee3b11e386bde84ecf7f78f31ca88e399c09fa09488821aee52836c147a920b9c891c2b65fe1c6b3ac4a6ca70bbdb66e88ff105804ab0c4ba00");
	// check that the value can be decoded
	let versioned_finality_proof_1 =
		VersionedFinalityProof::decode(&mut &encoded_versioned_finality_proof_1[..]);
	println!("versioned_finality_proof_1: {:?}", versioned_finality_proof_1);
	// leavesProof: {"blockHash":"0x71c766f9414325ef2c350349ac79123df427ed3bb9250d87997f87546849e53e","leaves":"0x044901000f00000040a1c43578f308d9f349e52cb094fe224b486ee0891e9d9bec15b10e8fbb37930100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900","proof":"0x040f00000000000000110000000000000014e497c56a44bd5595d2e5d7fab03853ad50ce69a76d366b2d35bcc2bb72e9395a411a84c1758f473c3ca88f8607153f805153e6e0f58510b40af019bd025421107a68cf5818c26afff0be34424545799d679846b08ad6801b60383863c5f4b128660e06dec777ea0fc1aabaaa5c71f93025785ed29a6e88aec7acda7680c208194c6c447cc3d80014a78c07eef12b2fa4b4941fde9bb0906b5c0ed123c2af4487"}
	let encoded_mmr_leaves_1 =  hex!("044901000f00000040a1c43578f308d9f349e52cb094fe224b486ee0891e9d9bec15b10e8fbb37930100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900");
	let encoded_mmr_proof_1 =  hex!("040f00000000000000110000000000000014e497c56a44bd5595d2e5d7fab03853ad50ce69a76d366b2d35bcc2bb72e9395a411a84c1758f473c3ca88f8607153f805153e6e0f58510b40af019bd025421107a68cf5818c26afff0be34424545799d679846b08ad6801b60383863c5f4b128660e06dec777ea0fc1aabaaa5c71f93025785ed29a6e88aec7acda7680c208194c6c447cc3d80014a78c07eef12b2fa4b4941fde9bb0906b5c0ed123c2af4487");

	assert!(lc
		.update_state(
			&encoded_versioned_finality_proof_1,
			&encoded_authority_set_proof,
			Some(&encoded_mmr_leaves_1),
			Some(&encoded_mmr_proof_1),
		)
		.is_ok());

	// versionedFinalityProof: {"version":1,"commitment":{"payload":[["0x6d68","0xb530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be1"]],"blockNumber":25,"validatorSetId":0},"signatures_from":"0xe0","validator_set_len":4,"signatures_compact":["0x3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801","0x992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00","0xbfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00"]}
	// encoded versionedFinalityProof: 0x01046d6880b530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be119000000000000000000000004e0040000000c3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00bfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00
	let encoded_versioned_finality_proof_2 = hex!("01046d6880b530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be119000000000000000000000004e0040000000c3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00bfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00");
	// check that the value can be decoded
	let versioned_finality_proof_2 =
		VersionedFinalityProof::decode(&mut &encoded_versioned_finality_proof_2[..]);
	println!("versioned_finality_proof_2: {:?}", versioned_finality_proof_2);
	// leavesProof: {"blockHash":"0x9ace34d4dcf39773de158da6ca9970ed9f7e4a3277c3d37744624fd3ec9d49ae","leaves":"0x0449010017000000f126e6251f6df464796796e2167e71517141d5042c72e1f5b678914cdaffadbd0100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900","proof":"0x041700000000000000190000000000000014ecbb56fad1763cfcf85065a1e7d3e640f25c24db82c9d547bba4f8a31813799b9278b1352647cba599641add3192dadd29d957d3df08da96e95356eecfcb4f297236345e4e4ea051ac330d46d80d3e8c7ec6e686ef91eb7eb1f7413e375eabfb7a15d088eef383c859b75daad24f0742176a12b0aed30ab5cd069b777e9395545900ca2d5603cc78df844a46b9cf56f4c3d274569400cbf0c994c4c41a58f90d"}
	let encoded_mmr_leaves_2 =  hex!("0449010017000000f126e6251f6df464796796e2167e71517141d5042c72e1f5b678914cdaffadbd0100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900");
	let encoded_mmr_proof_2 =  hex!("041700000000000000190000000000000014ecbb56fad1763cfcf85065a1e7d3e640f25c24db82c9d547bba4f8a31813799b9278b1352647cba599641add3192dadd29d957d3df08da96e95356eecfcb4f297236345e4e4ea051ac330d46d80d3e8c7ec6e686ef91eb7eb1f7413e375eabfb7a15d088eef383c859b75daad24f0742176a12b0aed30ab5cd069b777e9395545900ca2d5603cc78df844a46b9cf56f4c3d274569400cbf0c994c4c41a58f90d");

	assert!(lc
		.update_state(
			&encoded_versioned_finality_proof_2,
			&encoded_authority_set_proof,
			Some(&encoded_mmr_leaves_2),
			Some(&encoded_mmr_proof_2),
		)
		.is_ok());
}

#[test]
fn verify_solochain_messages_works() {
	let public_keys = vec![
		"0x020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1".to_string(), // Alice
		"0x0390084fdbf27d2b79d26a4f13f0ccd982cb755a661969143c37cbc49ef5b91f27".to_string(), // Bob
		"0x0389411795514af1627765eceffcbd002719f031604fadd7d188e2dc585b4e1afb".to_string(), // Charlie
		"0x03bc9d0ca094bd5b8b3225d7651eac5d18c1c04bf8ae8f8b263eebca4e1410ed0c".to_string(), // Dave
	];

	let mut lc = LightClient::new(public_keys);

	// versionedFinalityProof: {"version":1,"commitment":{"payload":[["0x6d68","0xb530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be1"]],"blockNumber":25,"validatorSetId":0},"signatures_from":"0xe0","validator_set_len":4,"signatures_compact":["0x3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801","0x992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00","0xbfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00"]}
	// encoded versionedFinalityProof: 0x01046d6880b530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be119000000000000000000000004e0040000000c3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00bfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00
	let versioned_finality_proof = hex!("01046d6880b530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be119000000000000000000000004e0040000000c3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00bfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00");
	let VersionedFinalityProof::V1(signed_commitment) =
		VersionedFinalityProof::decode(&mut &versioned_finality_proof[..]).unwrap();
	lc.latest_commitment = Some(signed_commitment.commitment);
	println!("light client: {:?}", lc);

	// Received message: {"blockNumber":19,"commitmentHash":"0x811a05884851c1dbf833a1d67c29ab696ac92ebac1da7d9c34c106d28a949cfa","crossChainMessages":"0x040400e90142000000307864343335393363373135666464333163363131343161626430346139396664363832326338353538383534636364653339613536383465376135366461323764100000007975616e6368616f2e746573746e6574000064a7b3b6e00d000000000000000000000000000000000000000000000000","header":"0x7394643b4e84fc3eb1966186927d733c6c8abdf56f7a9559870195cf99ec99914c56ea0c9afde0c4de4f2f6e5d124ae00bfc17ea81ce3fb53dd3d7b7e7da27f23ffba85c38007a337cfc45ec6e04f7fd03b815c1663d8acf2efbd795e984859f8e100642414245b501010100000026deb110000000001086a298e70633418902e9dad1793b60d9bf7017615709b25205f1a1626b0f0358478a801133a5a0b441692a633dee432410bf00fe4a295613a6da4dff39ab05d64440558b0ef9dc33450f05bfe684a5481894572dff49dbbd74a7e11cb9850c0080811a05884851c1dbf833a1d67c29ab696ac92ebac1da7d9c34c106d28a949cfa04424545468403d09e2ef41b15439b071206ab9e4bbac0d9ea249e720c95980c9a7ab0f23420d10542414245010150e8fe7ac1aac1bb65ba97fdffddbb12f6c7fcc91e88212b6f4da34a5c3c913ce0935cb163d265f58c900204bc9c5070c383f589a8c3a3dd56a29b625d05de83"}
	let messages = hex!("040400e90142000000307864343335393363373135666464333163363131343161626430346139396664363832326338353538383534636364653339613536383465376135366461323764100000007975616e6368616f2e746573746e6574000064a7b3b6e00d000000000000000000000000000000000000000000000000");
	let encoded_header = hex!("7394643b4e84fc3eb1966186927d733c6c8abdf56f7a9559870195cf99ec99914c56ea0c9afde0c4de4f2f6e5d124ae00bfc17ea81ce3fb53dd3d7b7e7da27f23ffba85c38007a337cfc45ec6e04f7fd03b815c1663d8acf2efbd795e984859f8e100642414245b501010100000026deb110000000001086a298e70633418902e9dad1793b60d9bf7017615709b25205f1a1626b0f0358478a801133a5a0b441692a633dee432410bf00fe4a295613a6da4dff39ab05d64440558b0ef9dc33450f05bfe684a5481894572dff49dbbd74a7e11cb9850c0080811a05884851c1dbf833a1d67c29ab696ac92ebac1da7d9c34c106d28a949cfa04424545468403d09e2ef41b15439b071206ab9e4bbac0d9ea249e720c95980c9a7ab0f23420d10542414245010150e8fe7ac1aac1bb65ba97fdffddbb12f6c7fcc91e88212b6f4da34a5c3c913ce0935cb163d265f58c900204bc9c5070c383f589a8c3a3dd56a29b625d05de83");

	// messageProof: {"blockHash":"0x9ace34d4dcf39773de158da6ca9970ed9f7e4a3277c3d37744624fd3ec9d49ae","leaves":"0x0449010013000000a92138977c1d23f02f6b51df11f3e1a8b42a6d5800d24d01942e787904212e060100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900","proof":"0x041300000000000000190000000000000014ecbb56fad1763cfcf85065a1e7d3e640f25c24db82c9d547bba4f8a31813799bcb2e83f7faa8c4dff84c30a61f05b512663cd4abe3019573e10407246fd7ae21618b7c72796828a9c7012009eefafb59e5e9a6a96577c4a755fd43596da6685a733ed3db28efc5a12975bd882c308d430f975590cbc68cfcb415a0306c71c0185900ca2d5603cc78df844a46b9cf56f4c3d274569400cbf0c994c4c41a58f90d"}
	let encoded_mmr_leaves =  hex!("0449010013000000a92138977c1d23f02f6b51df11f3e1a8b42a6d5800d24d01942e787904212e060100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900");
	let encoded_mmr_proof =  hex!("041300000000000000190000000000000014ecbb56fad1763cfcf85065a1e7d3e640f25c24db82c9d547bba4f8a31813799bcb2e83f7faa8c4dff84c30a61f05b512663cd4abe3019573e10407246fd7ae21618b7c72796828a9c7012009eefafb59e5e9a6a96577c4a755fd43596da6685a733ed3db28efc5a12975bd882c308d430f975590cbc68cfcb415a0306c71c0185900ca2d5603cc78df844a46b9cf56f4c3d274569400cbf0c994c4c41a58f90d");

	assert!(lc
		.verify_solochain_messages(
			&messages,
			&encoded_header,
			&encoded_mmr_leaves,
			&encoded_mmr_proof,
		)
		.is_ok());
}

#[test]
fn maximum_validators_test() {
	const MAX_VALIDATORS: i32 = 100;

	let secp = Secp256k1::new();

	let mut initial_public_keys = Vec::new();
	let versioned_finality_proof_example = hex!("01046d6880b530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be119000000000000000000000004e0040000000c3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00bfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00");
	let VersionedFinalityProof::V1(signed_commitment) =
		VersionedFinalityProof::decode(&mut &versioned_finality_proof_example[..]).unwrap();
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

	let mut lc = LightClient::new(vec!["0x00".to_string()]);
	lc.validator_set = BeefyNextAuthoritySet {
		id: 0,
		len: initial_public_keys.len() as u32,
		root: merkle_root::<Keccak256, _>(initial_public_keys.clone()),
	};
	let mut authority_set_proof = Vec::new();
	for i in 0..initial_public_keys.len() {
		let proof = merkle_proof::<Keccak256, _, _>(initial_public_keys.clone(), i);
		authority_set_proof.push(
			ValidatorMerkleProof {
				root: proof.root,
				proof: proof.proof.clone(),
				number_of_leaves: proof.number_of_leaves as u64,
				leaf_index: proof.leaf_index as u64,
				leaf: proof.leaf,
			}
			.encode(),
		);
	}

	println!("lc: {:?}", lc);

	let encoded_mmr_leaves =  hex!("0449010017000000f126e6251f6df464796796e2167e71517141d5042c72e1f5b678914cdaffadbd0100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900");
	let encoded_mmr_proof =  hex!("041700000000000000190000000000000014ecbb56fad1763cfcf85065a1e7d3e640f25c24db82c9d547bba4f8a31813799b9278b1352647cba599641add3192dadd29d957d3df08da96e95356eecfcb4f297236345e4e4ea051ac330d46d80d3e8c7ec6e686ef91eb7eb1f7413e375eabfb7a15d088eef383c859b75daad24f0742176a12b0aed30ab5cd069b777e9395545900ca2d5603cc78df844a46b9cf56f4c3d274569400cbf0c994c4c41a58f90d");
	assert!(lc
		.update_state(
			&encoded_versioned_finality_proof,
			&authority_set_proof,
			Some(&encoded_mmr_leaves),
			Some(&encoded_mmr_proof),
		)
		.is_ok());
	println!("lc: {:?}", lc);
}

#[test]
fn update_state_in_multiple_steps() {
	const MAX_VALIDATORS: i32 = 100;

	let secp = Secp256k1::new();

	let mut initial_public_keys = Vec::new();
	let versioned_finality_proof_example = hex!("01046d6880b530155bc78772edf61ce96692a3dc0a5bdf5f4cd942767314b29dc280463be119000000000000000000000004e0040000000c3c1fa45e174988a5a29a7807ef7cc9fa2dc4249aa2443a4af8ad79149f347eb6218a2657f03aded7436a23d63517126cc98d2f22b1588b7171b7c290c042b1d801992f8fecacdb97b0ea3a8b814bd6354d79e99d5fd9b75a4ca1833388c2813f2b25237cf63bc36bb82a617a7145025900c94be7597a2e2dfd9dc76719850f7afd00bfebf2f9906282d3c426e97ed0eaa867120cbcf59f74878ccc6c5b85e2ffb16f47c282483e505f225490ad9bcecb7178be7d2aacdfb6407409e54e280cf5e19e00");
	let VersionedFinalityProof::V1(signed_commitment) =
		VersionedFinalityProof::decode(&mut &versioned_finality_proof_example[..]).unwrap();
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

	let mut lc = LightClient::new(vec!["0x00".to_string()]);
	lc.validator_set = BeefyNextAuthoritySet {
		id: 0,
		len: initial_public_keys.len() as u32,
		root: merkle_root::<Keccak256, _>(initial_public_keys.clone()),
	};
	let mut authority_set_proof = Vec::new();
	for i in 0..initial_public_keys.len() {
		let proof = merkle_proof::<Keccak256, _, _>(initial_public_keys.clone(), i);
		authority_set_proof.push(
			ValidatorMerkleProof {
				root: proof.root,
				proof: proof.proof.clone(),
				number_of_leaves: proof.number_of_leaves as u64,
				leaf_index: proof.leaf_index as u64,
				leaf: proof.leaf,
			}
			.encode(),
		);
	}

	println!("lc: {:?}", lc);
	let encoded_mmr_leaves =  hex!("0449010017000000f126e6251f6df464796796e2167e71517141d5042c72e1f5b678914cdaffadbd0100000000000000040000002145814fb41496b2881ca364a06e320fd1bf2fa7b94e1e37325cefbe2905651900");
	let encoded_mmr_proof =  hex!("041700000000000000190000000000000014ecbb56fad1763cfcf85065a1e7d3e640f25c24db82c9d547bba4f8a31813799b9278b1352647cba599641add3192dadd29d957d3df08da96e95356eecfcb4f297236345e4e4ea051ac330d46d80d3e8c7ec6e686ef91eb7eb1f7413e375eabfb7a15d088eef383c859b75daad24f0742176a12b0aed30ab5cd069b777e9395545900ca2d5603cc78df844a46b9cf56f4c3d274569400cbf0c994c4c41a58f90d");
	assert!(lc
		.start_updating_state(
			&encoded_versioned_finality_proof,
			&authority_set_proof,
			&encoded_mmr_leaves,
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
