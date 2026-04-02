//! Symmetric cryptography algorithms for signing and verifying.

use std::{borrow::Cow, convert::Infallible, sync::Arc};

use hmac::{Hmac, KeyInit as _, Mac as _};
use secrecy::{ExposeSecret, SecretBox};

use huskarl_core::{
    crypto::{
        signer::{JwsSigner, JwsSignerSelector},
        verifier::{JwsVerifier, KeyMatch, KeyMatchStrength, VerifyError},
    },
    secrets::Secret,
};
use sha2::{Digest, digest::common::KeySizeUser as _};
use snafu::{ResultExt, Snafu, ensure};
use subtle::ConstantTimeEq as _;

/// Encodes which algorithm is used by this key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    /// HS256 algorithm
    Hs256,
    /// HS384 algorithm
    Hs384,
    /// HS512 algorithm
    Hs512,
}

impl AsRef<str> for SymmetricAlgorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
        }
    }
}

#[derive(Debug)]
struct SymmetricKeyInner {
    key: SecretBox<[u8]>,
    algorithm: SymmetricAlgorithm,
    key_id: Option<String>,
}

/// An HMAC symmetric key.
#[derive(Debug, Clone)]
pub struct SymmetricKey {
    inner: Arc<SymmetricKeyInner>,
}

/// An error that occurred while loading a symmetric key.
#[derive(Debug, Snafu)]
pub enum KeyLoadError<S: huskarl_core::Error> {
    /// The provided key had an incorrect length.
    InvalidKeySize {
        /// The size of the provided key.
        actual: usize,
        /// The key size.
        required: usize,
    },
    /// The secret could not be accessed.
    Secret {
        /// The underlying error.
        source: S,
    },
}

impl SymmetricKey {
    /// Loads the bytes from a binary secret.
    ///
    /// # Errors
    ///
    /// The secret could not be accessed.
    pub async fn load_bytes<
        S: Secret<Output = SecretBox<[u8]>>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        algorithm: SymmetricAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, KeyLoadError<S::Error>> {
        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let key_id = key_id_from_secret_identity(secret_output.identity.as_deref());
        let mut key = secret_output.value;

        let required_key_size = match algorithm {
            SymmetricAlgorithm::Hs256 => Hmac::<sha2::Sha256>::key_size(),
            SymmetricAlgorithm::Hs384 => Hmac::<sha2::Sha384>::key_size(),
            SymmetricAlgorithm::Hs512 => Hmac::<sha2::Sha512>::key_size(),
        };

        // Per RFC 2104: keys longer than the hash output size are first hashed
        // using the same hash function to derive the actual HMAC key.
        if key.expose_secret().len() > required_key_size {
            key = match algorithm {
                SymmetricAlgorithm::Hs256 => SecretBox::new(
                    sha2::Sha256::digest(key.expose_secret())
                        .to_vec()
                        .into_boxed_slice(),
                ),
                SymmetricAlgorithm::Hs384 => SecretBox::new(
                    sha2::Sha384::digest(key.expose_secret())
                        .to_vec()
                        .into_boxed_slice(),
                ),
                SymmetricAlgorithm::Hs512 => SecretBox::new(
                    sha2::Sha512::digest(key.expose_secret())
                        .to_vec()
                        .into_boxed_slice(),
                ),
            }
        }

        ensure!(
            key.expose_secret().len() == required_key_size,
            InvalidKeySizeSnafu {
                required: required_key_size,
                actual: key.expose_secret().len()
            }
        );

        Ok(Self {
            inner: Arc::new(SymmetricKeyInner {
                key,
                algorithm,
                key_id,
            }),
        })
    }
}

impl JwsSignerSelector for SymmetricKey {
    type Signer = Self;

    fn select_signer(&self) -> Self::Signer {
        self.clone()
    }
}

impl JwsSigner for SymmetricKey {
    type Error = Infallible;

    fn jws_algorithm(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.inner.algorithm.as_ref())
    }

    fn key_id(&self) -> Option<Cow<'_, str>> {
        self.inner.key_id.as_deref().map(Cow::Borrowed)
    }

    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key_bytes = self.inner.key.expose_secret();

        let signed_bytes = match self.inner.algorithm {
            SymmetricAlgorithm::Hs256 => {
                let mut key: Hmac<sha2::Sha256> = Hmac::new_from_slice(key_bytes)
                    .expect("Key length checked at construction time");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            SymmetricAlgorithm::Hs384 => {
                let mut key: Hmac<sha2::Sha384> = Hmac::new_from_slice(key_bytes)
                    .expect("Key length checked at construction time");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
            SymmetricAlgorithm::Hs512 => {
                let mut key: Hmac<sha2::Sha512> = Hmac::new_from_slice(key_bytes)
                    .expect("Key length checked at construction time");
                key.update(input);
                key.finalize().into_bytes().to_vec()
            }
        };

        Ok(signed_bytes)
    }
}

impl JwsVerifier for SymmetricKey {
    type Error = Infallible;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        if key_match.alg != self.inner.algorithm.as_ref() {
            return None;
        }

        if let Some(request_kid) = &key_match.kid {
            match &self.inner.key_id {
                Some(key_id) if key_id == request_kid => Some(KeyMatchStrength::ByKeyId),
                Some(_) => None,
                None => Some(KeyMatchStrength::ByAlgorithm),
            }
        } else {
            Some(KeyMatchStrength::ByAlgorithm)
        }
    }

    async fn verify(
        &self,
        input: &[u8],
        signature: &[u8],
        key_match: &KeyMatch<'_>,
    ) -> Result<(), VerifyError<Self::Error>> {
        if self.key_match(key_match).is_none() {
            return Err(VerifyError::NoMatchingKey);
        }

        let hashed_input = self
            .sign(input)
            .await
            .unwrap_or_else(|e: std::convert::Infallible| match e {});

        if hashed_input.ct_ne(signature).into() {
            return Err(VerifyError::SignatureMismatch);
        }

        Ok(())
    }
}
