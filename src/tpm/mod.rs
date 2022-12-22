#[cfg(feature = "tpm_fapi")]
pub mod fapi_wrapper;
#[cfg(feature = "tpm_fapi")]
pub mod keypair_fapi;
#[cfg(feature = "tpm_esys")]
pub mod esys_wrapper;
#[cfg(feature = "tpm_esys")]
pub mod keypair_esys;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("function {0} returned error code {1}")]
    TPMFapiError(&'static str, u32),

    #[error("esys wrapper error: {0}")]
    TPMEsapiError(String),

    #[error("bad key path {0}")]
    BadKeyPath(String),

    #[error("bad key handle {0}")]
    BadKeyHandle(u32),

    #[error("bad key type")]
    BadKeyType(),

    #[error("unexpected error: {0}")]
    Other(String),
}


