use super::commitment::Signature;
use super::Error;
use primitive_types::H256;

pub trait ValidatorRegistry {}

pub trait ECDSA {
	fn recover(&self, hash: H256, signature: Signature) -> Result<H256, Error>;
}
