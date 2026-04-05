//! AEAD encryptor/decryptor implementations.

use std::{array::TryFromSliceError, borrow::Cow};

use aes_gcm::{AeadInOut, aead::Generate};
use hmac::KeyInit;
use huskarl_core::{
    crypto::{
        KeyMatchStrength,
        cipher::{AeadDecryptor, AeadEncryptor, AeadOutput, CipherMatch},
    },
    secrets::{Secret, SecretBytes},
};
use sha2::digest::{
    array::Array,
    consts::{U12, U16},
    typenum::Unsigned,
};
use snafu::prelude::*;

/// The type of key to generate.
pub enum AesGcmKeyType {
    /// AES-GCM-128
    Aes128,
    /// AES-GCM-256
    Aes256,
}

enum NativeKey {
    Aes128(aes_gcm::Aes128Gcm),
    Aes256(aes_gcm::Aes256Gcm),
}

impl NativeKey {
    pub fn enc_algorithm(&self) -> &'static str {
        match self {
            NativeKey::Aes128(_) => "A128GCM",
            NativeKey::Aes256(_) => "A256GCM",
        }
    }
}

/// An AES-GCM key.
pub struct AesGcmKey {
    inner: NativeKey,
    kid: Option<String>,
}

/// Errors that can occur when loading a key.
#[derive(Debug, Snafu)]
pub enum LoadKeyError<Sec: huskarl_core::Error> {
    /// There was an error fetching the secret.
    Secret {
        /// The underlying secret.
        source: Sec,
    },
    /// The key had the incorrect length;
    InvalidKeyLength,
}

impl AesGcmKey {
    /// Load a key from a secret.
    pub async fn from_secret<S: Secret<Output = SecretBytes>>(
        key_type: AesGcmKeyType,
        secret: S,
        kid_from_identity: impl Fn(Option<&str>) -> Option<String>,
    ) -> Result<Self, LoadKeyError<S::Error>> {
        let key_source = secret.get_secret_value().await.context(SecretSnafu)?;

        let inner = match key_type {
            AesGcmKeyType::Aes128 => NativeKey::Aes128(
                aes_gcm::Aes128Gcm::new_from_slice(key_source.value.expose_secret())
                    .map_err(|_| InvalidKeyLengthSnafu.build())?,
            ),
            AesGcmKeyType::Aes256 => NativeKey::Aes256(
                aes_gcm::Aes256Gcm::new_from_slice(key_source.value.expose_secret())
                    .map_err(|_| InvalidKeyLengthSnafu.build())?,
            ),
        };

        Ok(AesGcmKey {
            inner,
            kid: kid_from_identity(key_source.identity.as_deref()),
        })
    }
}

/// Errors that can occur during AEAD operations.
#[derive(Debug, Snafu)]
pub enum AesGcmError {
    /// An error occurred when decrypting the ciphertext.
    Decrypt {
        /// The underlying error.
        source: aes_gcm::Error,
    },
    /// An error occurred when encrypting the plaintext.
    Encrypt {
        /// The underlying error.
        source: aes_gcm::Error,
    },
    /// The supplied nonce had an invalid length.
    InvalidNonce {
        /// The underlying error.
        source: TryFromSliceError,
    },
    /// The supplied tag had an invalid length.
    InvalidTag {
        /// The underlying error.
        source: TryFromSliceError,
    },
}

impl huskarl_core::Error for AesGcmError {
    fn is_retryable(&self) -> bool {
        false
    }
}

impl AeadEncryptor for AesGcmKey {
    type Error = AesGcmError;

    fn enc_algorithm(&self) -> std::borrow::Cow<'_, str> {
        Cow::Borrowed(self.inner.enc_algorithm())
    }

    fn key_id(&self) -> Option<std::borrow::Cow<'_, str>> {
        self.kid.as_deref().map(Cow::Borrowed)
    }

    async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<AeadOutput, Self::Error> {
        let nonce = Array::generate();
        let mut ciphertext = plaintext.to_vec();

        let tag = match &self.inner {
            NativeKey::Aes128(aes_gcm) => {
                aes_gcm.encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
            }
            NativeKey::Aes256(aes_gcm) => {
                aes_gcm.encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
            }
        }
        .context(EncryptSnafu)?;

        Ok(AeadOutput {
            nonce: nonce.into(),
            ciphertext,
            tag: tag.into(),
        })
    }
}

impl AeadDecryptor for AesGcmKey {
    type Error = AesGcmError;

    fn nonce_length(&self) -> usize {
        U12::to_usize()
    }

    fn tag_length(&self) -> usize {
        U16::to_usize()
    }

    fn cipher_match(&self, m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        if m.enc != self.inner.enc_algorithm() {
            return None;
        }

        match (m.kid, self.kid.as_deref()) {
            (Some(header_kid), Some(self_kid)) => {
                if header_kid == self_kid {
                    Some(KeyMatchStrength::ByKeyId)
                } else {
                    None
                }
            }
            _ => Some(KeyMatchStrength::ByAlgorithm),
        }
    }

    async fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let nonce = nonce.try_into().context(InvalidNonceSnafu)?;
        let tag = tag.try_into().context(InvalidTagSnafu)?;
        let mut plaintext = ciphertext.to_vec();

        match &self.inner {
            NativeKey::Aes128(aes_gcm) => {
                aes_gcm.decrypt_inout_detached(&nonce, aad, plaintext.as_mut_slice().into(), &tag)
            }
            NativeKey::Aes256(aes_gcm) => {
                aes_gcm.decrypt_inout_detached(&nonce, aad, plaintext.as_mut_slice().into(), &tag)
            }
        }
        .context(DecryptSnafu)?;

        Ok(plaintext)
    }
}
