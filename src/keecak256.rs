// use hash_db::Hasher;
//
// mod keccak256 {
//     use crate::Hash;
//     use tiny_keccak::{Hasher as _, Keccak};
//     use sp_runtime::StateVersion;
//     use sp_core::RuntimeDebug;
//
//     #[derive(PartialEq, Eq, Clone, RuntimeDebug)]
//     /// Keccak256 hasher implementation.
//     pub struct Keccak256;
//     impl Keccak256 {
//         /// Hash given data.
//         pub fn hash(data: &[u8]) -> Hash {
//             <Keccak256 as super::Hasher>::hash(data)
//         }
//     }
//     impl super::Hasher for Keccak256 {
//         type Out = Hash;
//         type StdHasher = hash256_std_hasher::Hash256StdHasher;
//         const LENGTH: usize = 32;
//         fn hash(data: &[u8]) -> Hash {
//             let mut keccak = Keccak::v256();
//             keccak.update(data);
//             let mut output = [0_u8; 32];
//             keccak.finalize(&mut output);
//             output
//         }
//     }
//
//     impl sp_runtime::traits::Hash for Keccak256 {
//         type Output = Hash;
//
//         fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
//             sp_io::trie::keccak_256_root(input, version)
//         }
//
//         fn ordered_trie_root(input: Vec<Vec<u8>>, version: StateVersion) -> Self::Output {
//             sp_io::trie::keccak_256_ordered_root(input, version)
//         }
//     }
// }
// pub use keccak256::Keccak256;
