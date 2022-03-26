use std::{
    convert::{TryFrom, TryInto},
    ffi::CString, mem::MaybeUninit, os::raw::c_char, ptr::null_mut, sync::Once,
};
use std::ffi::CStr;
use std::sync::Mutex;

use p256::ecdsa;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tss2::{
    FAPI_CONTEXT, TSS2_RC, TSS2_RC_SUCCESS, ESYS_TR, FAPI_ESYSBLOB_CONTEXTLOAD, TPMS_CONTEXT,
    TSS2_TCTI_CONTEXT, ESYS_CONTEXT, TPM2B_ECC_POINT, ESYS_TR_PASSWORD, ESYS_TR_NONE,
    TPM2B_PUBLIC, TPM2B_NAME,
    size_t, UINT16, BYTE,
    Tss2_MU_TPMS_CONTEXT_Unmarshal,
    Esys_Initialize, Esys_ContextLoad, Esys_ECDH_ZGen, Esys_FlushContext, Esys_Finalize, Esys_ReadPublic,
    Fapi_Initialize, Fapi_GetEsysBlob, Fapi_GetTcti, Fapi_Sign
};

use crate::{keypair, KeyTag, Network, public_key, Result, KeyType as CrateKeyType};

use crate::{
    ecc_compact, ecc_compact::Signature,
};

//include!("/home/iegor/work/projects/helium-crypto-rs/target/debug/build/tss2-44292ec18120c6c4/out/tss2.rs");

#[derive(Debug, Error)]
pub enum Error {
    #[error("functions {0} returned error code {1}")]
    TPMError(String, u32),

    #[error("wrong key path")]
    WrongKeyPath,
}

impl Error {
    pub fn tpm_error(func: String, code: u32) -> crate::Error {
        Self::TPMError(func, code).into()
    }

    pub fn wrong_key_path() -> crate::Error {
        Self::WrongKeyPath.into()
    }
}


static INIT: Once = Once::new();
static mut TPM_CTX: Option<Mutex<*mut FAPI_CONTEXT>> = None;

fn tpm<'a>() -> &'a Mutex<*mut FAPI_CONTEXT> {
    unsafe { TPM_CTX.as_ref().unwrap() }
}

pub fn with_tpm<F, R>(f: F) -> R
    where
        F: FnOnce(*mut FAPI_CONTEXT) -> R,
{
    let mut tpm_ctx = tpm().lock().unwrap();
    f(*tpm_ctx)
}


pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    pub path: String,
}

impl PartialEq<Self> for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.path == other.path
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("path", &self.path)
            .field("public", &self.public_key)
            .finish()
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

pub fn init() -> Result {
    if INIT.is_completed() {
        return Ok(());
    }

    unsafe {
        let mut res: TSS2_RC = TSS2_RC_SUCCESS;

        let mut tpm_ctx: *mut FAPI_CONTEXT = MaybeUninit::uninit().assume_init();
        res = Fapi_Initialize(&mut tpm_ctx as *mut *mut FAPI_CONTEXT, null_mut());
        if res != TSS2_RC_SUCCESS {
            return Err(Error::tpm_error(String::from("Fapi_Initialize"), res));
        }

        INIT.call_once(|| {
            TPM_CTX = Some(Mutex::new(tpm_ctx));
        });
    }

    Ok(())
}

impl Keypair {
    pub fn from_key_path(network: Network, key_path: String) -> Result<Keypair> {
        let bytes: Vec<BYTE> = Self::public_key(&key_path)?;
        let mut key_bytes = vec![4u8];
        key_bytes.extend_from_slice(bytes.as_slice());
        let public_key = ecc_compact::PublicKey::try_from(key_bytes.as_ref())?;
        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, public_key),
            path: key_path
        })
    }

    fn public_key(key_path: &String) -> Result<Vec<BYTE>> {
        unsafe {
            let mut result: TSS2_RC = TSS2_RC_SUCCESS;
            let mut esys_key_handle: ESYS_TR = 0;
            let mut blob_type: u8 = 0;
            let mut esys_blob: *mut u8 = null_mut();
            let mut blob_sz: size_t = 0;
            let mut offset: size_t = 0;
            result = with_tpm(|tpm_ctx| Fapi_GetEsysBlob(tpm_ctx,
                                        CString::new(key_path.as_bytes()).unwrap().as_ptr(),
                                        &mut blob_type as *mut u8 ,
                                        &mut esys_blob as *mut *mut u8,
                                        &mut blob_sz as *mut size_t));
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Fapi_GetEsysBlob"), result));
            }
            if blob_type != FAPI_ESYSBLOB_CONTEXTLOAD as u8 {
                return Err(Error::wrong_key_path());
            }

            let mut key_context: TPMS_CONTEXT = MaybeUninit::uninit().assume_init();
            result = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob,
                                                    blob_sz,
                                                    &mut offset as *mut size_t,
                                                    &mut key_context as *mut TPMS_CONTEXT);
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Tss2_MU_TPMS_CONTEXT_Unmarshal"), result));
            }

            let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = null_mut();
            result = with_tpm(|tpm_ctx|Fapi_GetTcti(tpm_ctx, &mut tcti_ctx as *mut *mut TSS2_TCTI_CONTEXT));
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Fapi_GetTcti"), result));
            }

            let mut esys_ctx: *mut ESYS_CONTEXT = null_mut();
            result = Esys_Initialize(&mut esys_ctx as *mut *mut ESYS_CONTEXT, tcti_ctx, null_mut());
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Esys_Initialize"), result));
            }

            result = Esys_ContextLoad(esys_ctx, &mut key_context as *mut TPMS_CONTEXT, &mut esys_key_handle as *mut ESYS_TR);
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Esys_ContextLoad"), result));
            }

            let mut public_part: *mut TPM2B_PUBLIC = null_mut();
            let mut public_name: *mut TPM2B_NAME = null_mut();
            let mut qualif_name: *mut TPM2B_NAME = null_mut();
            result = Esys_ReadPublic(esys_ctx,
                                    esys_key_handle,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    &mut public_part as *mut *mut TPM2B_PUBLIC,
                                    &mut public_name as *mut *mut TPM2B_NAME,
                                    &mut qualif_name as *mut *mut TPM2B_NAME);
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Esys_ReadPublic"), result));
            }

            let ecc_point = (*public_part).publicArea.unique.ecc;
            let mut key_bytes = Vec::new();
            key_bytes.extend_from_slice(&ecc_point.x.buffer.as_slice()[..ecc_point.x.size as usize]);
            key_bytes.extend_from_slice(&ecc_point.y.buffer.as_slice()[..ecc_point.y.size as usize]);

            Ok(key_bytes)
        }
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: CrateKeyType::EccCompact,
        }
    }

    pub fn ecdh<'a, C>(&self, public_key: C) -> Result<ecc_compact::SharedSecret>
        where
            C: TryInto<&'a p256::PublicKey, Error = Error>,
    {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let key = public_key.try_into()?;
        let point = key.to_encoded_point(false);

        unsafe {
            let mut result: TSS2_RC;
            let mut esys_key_handle: ESYS_TR = MaybeUninit::uninit().assume_init();
            let mut blob_type: u8 = 0;
            let mut esys_blob: *mut u8 = null_mut();
            let mut blob_sz: size_t = 0;
            let mut offset: size_t = 0;

            result = with_tpm(|tpm_ctx|Fapi_GetEsysBlob(tpm_ctx,
                                      CString::new(self.path.as_bytes()).unwrap().as_ptr(),
                                      &mut blob_type as *mut u8,
                                      &mut esys_blob as *mut *mut u8,
                                      &mut blob_sz as *mut size_t));

            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Fapi_GetEsysBlob"),result));
            }

            if blob_type != FAPI_ESYSBLOB_CONTEXTLOAD as u8 {
                return Err(Error::wrong_key_path());
            }

            let mut key_context: TPMS_CONTEXT = MaybeUninit::uninit().assume_init();
            result = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob, blob_sz, &mut offset as *mut size_t, &mut key_context as *mut TPMS_CONTEXT);
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Tss2_MU_TPMS_CONTEXT_Unmarshal"),result));
            }

            let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = null_mut();
            result = with_tpm(|tpm_ctx|Fapi_GetTcti(tpm_ctx, &mut tcti_ctx as *mut *mut TSS2_TCTI_CONTEXT));
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Fapi_GetTcti"),result));
            }

            let mut esys_ctx: *mut ESYS_CONTEXT = null_mut();
            result = Esys_Initialize(&mut esys_ctx as *mut *mut ESYS_CONTEXT, tcti_ctx, null_mut());
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Esys_Initialize"),result));
            }

            result = Esys_ContextLoad(esys_ctx, &mut key_context as *mut TPMS_CONTEXT, &mut esys_key_handle as *mut ESYS_TR);
            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Esys_ContextLoad"),result));
            }

            let mut secret: *mut TPM2B_ECC_POINT = null_mut();
            let mut pub_point: TPM2B_ECC_POINT = MaybeUninit::uninit().assume_init();
            pub_point.point.x.size = point.x().unwrap().len() as UINT16;
            pub_point.point.x.buffer.copy_from_slice(point.x().unwrap().as_slice());

            pub_point.point.y.size = point.y().unwrap().len() as UINT16;
            pub_point.point.y.buffer.copy_from_slice(point.y().unwrap().as_slice());
            pub_point.size = pub_point.point.x.size + pub_point.point.y.size;

            result = Esys_ECDH_ZGen(esys_ctx,
                                    esys_key_handle,
                                    ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE,
                                    ESYS_TR_NONE,
                                    &mut pub_point as *mut TPM2B_ECC_POINT,
                                    &mut secret as *mut *mut TPM2B_ECC_POINT);


            if result != TSS2_RC_SUCCESS {
                return Err(Error::tpm_error(String::from("Esys_ECDH_ZGen"),result));
            }

            Esys_FlushContext(esys_ctx, esys_key_handle);
            Esys_Finalize(&mut esys_ctx as *mut *mut ESYS_CONTEXT);

            let mut shared_secret_bytes = Vec::new();
            shared_secret_bytes.extend_from_slice(&(*secret).point.x.buffer.as_slice()[..(*secret).point.x.size as usize]);
            shared_secret_bytes.extend_from_slice(&(*secret).point.y.buffer.as_slice()[..(*secret).point.y.size as usize]);


            Ok(ecc_compact::SharedSecret(p256::ecdh::SharedSecret::from(
                *p256::FieldBytes::from_slice(shared_secret_bytes.as_slice()))
            ))
        }
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        unsafe {
            let digest = Sha256::digest(msg);
            let mut raw_signature: *mut u8 = null_mut();
            let mut signature_sz: size_t = 0;
            let mut public_key: *mut c_char = null_mut();
            let mut certificate: *mut c_char = null_mut();
            let result = with_tpm(|tpm_ctx|Fapi_Sign(tpm_ctx,
                                   CString::new(self.path.as_bytes()).unwrap().as_ptr(),
                                   null_mut(),
                                   digest.as_ptr(),
                                   digest.len() as size_t,
                                   &mut raw_signature as *mut *mut u8,
                                   &mut signature_sz as *mut size_t,
                                   &mut public_key as *mut *mut c_char,
                                   &mut certificate as *mut *mut c_char));

            if result != TSS2_RC_SUCCESS {
                return Err(signature::Error::from_source(Error::tpm_error(String::from("Fapi_Sign"),result)));
            }

            let sign_slice= std::slice::from_raw_parts(raw_signature, signature_sz as usize);
            let signature = ecdsa::Signature::from_der(&sign_slice[..])?;
            Ok(Signature(signature))
        }
    }
}