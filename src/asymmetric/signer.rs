//! Signing code for asymmetric keys.

use pkcs8::DecodePrivateKey;
use rand::Rng;
use rsa::traits::PublicKeyParts as _;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use signature::{SignatureEncoding, Signer as _};
use snafu::prelude::*;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;

use huskarl_core::crypto::signer::{HasPublicKey, JwsSigningKey, SigningKeyMetadata};
use huskarl_core::jwk;
use huskarl_core::secrets::Secret;

/// Errors that may occur when loading the private key.
#[derive(Debug, Snafu)]
pub enum KeyLoadError<E: huskarl_core::Error> {
    /// Failed to access secret information.
    Secret {
        /// The underlying error.
        source: E,
    },
    /// Failed to decode PKCS#8 key
    #[snafu(display("Failed to decode PKCS#8 key"))]
    KeyDecode {
        /// The underlying error.
        source: pkcs8::Error,
    },
}

#[derive(Debug)]
struct PrivateKeyInner {
    signing_key: Key,
    key_metadata: SigningKeyMetadata,
    jwk: jwk::PublicJwk,
}

/// An asymmetric private key.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    inner: Arc<PrivateKeyInner>,
}

#[derive(Debug)]
enum Key {
    Es256(p256::ecdsa::SigningKey),
    Es384(p384::ecdsa::SigningKey),
    Rs256(rsa::pkcs1v15::SigningKey<sha2::Sha256>),
    Rs384(rsa::pkcs1v15::SigningKey<sha2::Sha384>),
    Rs512(rsa::pkcs1v15::SigningKey<sha2::Sha512>),
    Ps256(rsa::pss::SigningKey<sha2::Sha256>),
    Ps384(rsa::pss::SigningKey<sha2::Sha384>),
    Ps512(rsa::pss::SigningKey<sha2::Sha512>),
    Ed25519 {
        key: ed25519_dalek::SigningKey,
        use_fully_specified_jws_algorithm: bool,
    },
}

impl Key {
    pub const fn jws_algorithm(&self) -> &'static str {
        match self {
            Key::Es256(_) => "ES256",
            Key::Es384(_) => "ES384",
            Key::Rs256(_) => "RS256",
            Key::Rs384(_) => "RS384",
            Key::Rs512(_) => "RS512",
            Key::Ps256(_) => "PS256",
            Key::Ps384(_) => "PS384",
            Key::Ps512(_) => "PS512",
            Key::Ed25519 {
                use_fully_specified_jws_algorithm: true,
                ..
            } => "Ed25519",
            Key::Ed25519 {
                use_fully_specified_jws_algorithm: false,
                ..
            } => "EdDSA",
        }
    }

    pub fn as_public_jwk(&self, kid: Option<&str>) -> jwk::PublicJwk {
        match self {
            Key::Es256(signing_key) => {
                let point = p256::ecdsa::VerifyingKey::from(signing_key).to_sec1_point(false);
                let x = point
                    .x()
                    .expect("uncompressed point always has x coordinate")
                    .to_vec();
                let y = point
                    .y()
                    .expect("uncompressed point always has a y coordinate")
                    .to_vec();

                jwk::PublicJwk::builder()
                    .algorithm(self.jws_algorithm())
                    .maybe_kid(kid)
                    .key_use(jwk::KeyUse::Sign)
                    .key(jwk::EcPublicKey::builder().crv("P-256").x(x).y(y).build())
                    .build()
            }
            Key::Es384(signing_key) => {
                let point = p384::ecdsa::VerifyingKey::from(signing_key).to_sec1_point(false);
                let x = point
                    .x()
                    .expect("uncompressed point always has x coordinate")
                    .to_vec();
                let y = point
                    .y()
                    .expect("uncompressed point always has a y coordinate")
                    .to_vec();

                jwk::PublicJwk::builder()
                    .algorithm(self.jws_algorithm())
                    .maybe_kid(kid)
                    .key_use(jwk::KeyUse::Sign)
                    .key(jwk::EcPublicKey::builder().crv("P-384").x(x).y(y).build())
                    .build()
            }
            Key::Rs256(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Rs384(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Rs512(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ps256(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ps384(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ps512(signing_key) => {
                convert_rsa_public_key_to_jwk(signing_key, kid, self.jws_algorithm())
            }
            Key::Ed25519 { key, .. } => jwk::PublicJwk::builder()
                .algorithm(self.jws_algorithm())
                .maybe_kid(kid)
                .key_use(jwk::KeyUse::Sign)
                .key(
                    jwk::OkpPublicKey::builder()
                        .crv("Ed25519")
                        .x(*key.verifying_key().as_bytes())
                        .build(),
                )
                .build(),
        }
    }
}

fn convert_rsa_public_key_to_jwk(
    private_key: impl AsRef<rsa::RsaPrivateKey>,
    kid: Option<&str>,
    alg: &str,
) -> jwk::PublicJwk {
    let public_key = private_key.as_ref().to_public_key();

    jwk::PublicJwk::builder()
        .algorithm(alg)
        .maybe_kid(kid)
        .key_use(jwk::KeyUse::Sign)
        .key(
            jwk::RsaPublicKey::builder()
                .e(public_key.e().to_be_bytes())
                .n(public_key.n().to_be_bytes())
                .build(),
        )
        .build()
}

/// RSA modulus length of 2048 bits (current minimum).
pub const RSA_MODULUS_2048: u32 = 2048;

/// RSA modulus length of 3072 bits (commonly recommended).
pub const RSA_MODULUS_3072: u32 = 3072;

/// RSA modulus length of 4096 bits.
pub const RSA_MODULUS_4096: u32 = 4096;

/// Asymmetric algorithm for key generation, including RSA key parameters.
///
/// Used with [`PrivateKey::generate`]. For loading existing keys from PKCS#8,
/// use [`AsymmetricAlgorithm`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateAlgorithm {
    /// ES256
    Es256,
    /// ES384
    Es384,
    /// RS256
    Rs256 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// RS384
    Rs384 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// RS512
    Rs512 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// PS256
    Ps256 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// PS384
    Ps384 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// PS512
    Ps512 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// Ed25519, using the algorithm name `EdDSA`
    EdDsa,
    /// Ed25519, using the algorithm name Ed25519
    Ed25519,
}

/// Asymmetric algorithm for signing.
///
/// Used with [`PrivateKey::load_pkcs8_der`] and [`PrivateKey::load_pkcs8_pem`].
/// For generating new keys, use [`GenerateAlgorithm`] with [`PrivateKey::generate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetricAlgorithm {
    /// ES256
    Es256,
    /// ES384
    Es384,
    /// RS256
    Rs256,
    /// RS384
    Rs384,
    /// RS512
    Rs512,
    /// PS256
    Ps256,
    /// PS384
    Ps384,
    /// PS512
    Ps512,
    /// Ed25519, using the algorithm name `EdDSA`
    EdDsa,
    /// Ed25519, using the algorithm name Ed25519
    Ed25519,
}

impl AsRef<str> for AsymmetricAlgorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::EdDsa => "EdDSA",
            Self::Ed25519 => "Ed25519",
        }
    }
}

impl PrivateKey {
    /// Generates an asymmetric key in memory.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn generate(key_type: GenerateAlgorithm) -> Self {
        let signing_key = match key_type {
            GenerateAlgorithm::Es256 => {
                use p256::elliptic_curve::Generate as _;
                Key::Es256(p256::ecdsa::SigningKey::generate())
            }
            GenerateAlgorithm::Es384 => {
                use p384::elliptic_curve::Generate as _;
                Key::Es384(p384::ecdsa::SigningKey::generate())
            }
            GenerateAlgorithm::Rs256 { modulus_length } => {
                Key::Rs256(rsa::pkcs1v15::SigningKey::new(
                    rsa::RsaPrivateKey::new(&mut rand::rng(), modulus_length as usize)
                        .expect("Key is >= 1024 bytes"),
                ))
            }
            GenerateAlgorithm::Rs384 { modulus_length } => {
                Key::Rs384(rsa::pkcs1v15::SigningKey::new(
                    rsa::RsaPrivateKey::new(&mut rand::rng(), modulus_length as usize)
                        .expect("Key is >= 1024 bytes"),
                ))
            }
            GenerateAlgorithm::Rs512 { modulus_length } => {
                Key::Rs512(rsa::pkcs1v15::SigningKey::new(
                    rsa::RsaPrivateKey::new(&mut rand::rng(), modulus_length as usize)
                        .expect("Key is >= 1024 bytes"),
                ))
            }
            GenerateAlgorithm::Ps256 { modulus_length } => Key::Ps256(rsa::pss::SigningKey::new(
                rsa::RsaPrivateKey::new(&mut rand::rng(), modulus_length as usize)
                    .expect("Key is >= 1024 bytes"),
            )),
            GenerateAlgorithm::Ps384 { modulus_length } => Key::Ps384(rsa::pss::SigningKey::new(
                rsa::RsaPrivateKey::new(&mut rand::rng(), modulus_length as usize)
                    .expect("Key is >= 1024 bytes"),
            )),
            GenerateAlgorithm::Ps512 { modulus_length } => Key::Ps512(rsa::pss::SigningKey::new(
                rsa::RsaPrivateKey::new(&mut rand::rng(), modulus_length as usize)
                    .expect("Key is >= 1024 bytes"),
            )),
            GenerateAlgorithm::EdDsa => {
                let mut secret = [0u8; 32];
                rand::rng().fill_bytes(&mut secret);
                Key::Ed25519 {
                    key: ed25519_dalek::SigningKey::from_bytes(&secret),
                    use_fully_specified_jws_algorithm: false,
                }
            }
            GenerateAlgorithm::Ed25519 => {
                let mut secret = [0u8; 32];
                rand::rng().fill_bytes(&mut secret);
                Key::Ed25519 {
                    key: ed25519_dalek::SigningKey::from_bytes(&secret),
                    use_fully_specified_jws_algorithm: true,
                }
            }
        };

        let jws_algorithm = signing_key.jws_algorithm().to_string();
        let jwk = signing_key.as_public_jwk(None);

        Self {
            inner: Arc::new(PrivateKeyInner {
                signing_key,
                key_metadata: SigningKeyMetadata {
                    jws_algorithm,
                    key_id: None,
                },
                jwk,
            }),
        }
    }

    /// Loads the private key from a DER binary secret.
    ///
    /// # Errors
    ///
    /// The secret was not a valid DER formatted secret, or the secret
    /// could not be accessed.
    pub async fn load_pkcs8_der<
        S: Secret<Output = SecretBox<[u8]>>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        key_type: AsymmetricAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, KeyLoadError<S::Error>> {
        fn build(
            key_id: Option<String>,
            f: impl Fn() -> Result<Key, pkcs8::Error>,
        ) -> Result<PrivateKey, pkcs8::Error> {
            let signing_key = f()?;
            let jws_algorithm = signing_key.jws_algorithm().to_string();
            let jwk = signing_key.as_public_jwk(key_id.as_deref());

            Ok(PrivateKey {
                inner: Arc::new(PrivateKeyInner {
                    signing_key,
                    key_metadata: SigningKeyMetadata {
                        jws_algorithm,
                        key_id,
                    },
                    jwk,
                }),
            })
        }

        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let bytes = secret_output.value.expose_secret();
        let key_id = key_id_from_secret_identity(secret_output.identity.as_deref());

        match key_type {
            AsymmetricAlgorithm::Es256 => build(key_id, || {
                p256::ecdsa::SigningKey::from_pkcs8_der(bytes).map(Key::Es256)
            }),
            AsymmetricAlgorithm::Es384 => build(key_id, || {
                p384::ecdsa::SigningKey::from_pkcs8_der(bytes).map(Key::Es384)
            }),
            AsymmetricAlgorithm::Rs256 => build(key_id, || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_der(bytes).map(Key::Rs256)
            }),
            AsymmetricAlgorithm::Rs384 => build(key_id, || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_der(bytes).map(Key::Rs384)
            }),
            AsymmetricAlgorithm::Rs512 => build(key_id, || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_der(bytes).map(Key::Rs512)
            }),
            AsymmetricAlgorithm::Ps256 => build(key_id, || {
                rsa::pss::SigningKey::from_pkcs8_der(bytes).map(Key::Ps256)
            }),
            AsymmetricAlgorithm::Ps384 => build(key_id, || {
                rsa::pss::SigningKey::from_pkcs8_der(bytes).map(Key::Ps384)
            }),
            AsymmetricAlgorithm::Ps512 => build(key_id, || {
                rsa::pss::SigningKey::from_pkcs8_der(bytes).map(Key::Ps512)
            }),
            AsymmetricAlgorithm::EdDsa => build(key_id, || {
                ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: false,
                })
            }),
            AsymmetricAlgorithm::Ed25519 => build(key_id, || {
                ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: true,
                })
            }),
        }
        .context(KeyDecodeSnafu)
    }

    /// Loads the private key from a PKCS#8 PEM secret.
    ///
    /// # Errors
    ///
    /// The secret was not a valid PKCS#8 PEM formatted string, or
    /// the secret could not be accessed.
    pub async fn load_pkcs8_pem<
        S: Secret<Output = SecretString>,
        F: FnOnce(Option<&str>) -> Option<String>,
    >(
        secret: S,
        key_type: AsymmetricAlgorithm,
        key_id_from_secret_identity: F,
    ) -> Result<Self, KeyLoadError<S::Error>> {
        fn build(
            key_id: Option<String>,
            f: impl Fn() -> Result<Key, pkcs8::Error>,
        ) -> Result<PrivateKey, pkcs8::Error> {
            let signing_key = f()?;
            let jws_algorithm = signing_key.jws_algorithm().to_string();
            let jwk = signing_key.as_public_jwk(key_id.as_deref());

            Ok(PrivateKey {
                inner: Arc::new(PrivateKeyInner {
                    signing_key,
                    key_metadata: SigningKeyMetadata {
                        jws_algorithm,
                        key_id,
                    },
                    jwk,
                }),
            })
        }

        let secret_output = secret.get_secret_value().await.context(SecretSnafu)?;
        let bytes = secret_output.value.expose_secret();
        let key_id = key_id_from_secret_identity(secret_output.identity.as_deref());

        match key_type {
            AsymmetricAlgorithm::Es256 => build(key_id, || {
                p256::ecdsa::SigningKey::from_pkcs8_pem(bytes).map(Key::Es256)
            }),
            AsymmetricAlgorithm::Es384 => build(key_id, || {
                p384::ecdsa::SigningKey::from_pkcs8_pem(bytes).map(Key::Es384)
            }),
            AsymmetricAlgorithm::Rs256 => build(key_id, || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_pem(bytes).map(Key::Rs256)
            }),
            AsymmetricAlgorithm::Rs384 => build(key_id, || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_pem(bytes).map(Key::Rs384)
            }),
            AsymmetricAlgorithm::Rs512 => build(key_id, || {
                rsa::pkcs1v15::SigningKey::from_pkcs8_pem(bytes).map(Key::Rs512)
            }),
            AsymmetricAlgorithm::Ps256 => build(key_id, || {
                rsa::pss::SigningKey::from_pkcs8_pem(bytes).map(Key::Ps256)
            }),
            AsymmetricAlgorithm::Ps384 => build(key_id, || {
                rsa::pss::SigningKey::from_pkcs8_pem(bytes).map(Key::Ps384)
            }),
            AsymmetricAlgorithm::Ps512 => build(key_id, || {
                rsa::pss::SigningKey::from_pkcs8_pem(bytes).map(Key::Ps512)
            }),
            AsymmetricAlgorithm::EdDsa => build(key_id, || {
                ed25519_dalek::SigningKey::from_pkcs8_pem(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: false,
                })
            }),
            AsymmetricAlgorithm::Ed25519 => build(key_id, || {
                ed25519_dalek::SigningKey::from_pkcs8_pem(bytes).map(|key| Key::Ed25519 {
                    key,
                    use_fully_specified_jws_algorithm: true,
                })
            }),
        }
        .context(KeyDecodeSnafu)
    }
}

impl JwsSigningKey for PrivateKey {
    type Error = Infallible;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match &self.inner.signing_key {
            Key::Es256(signing_key) => {
                let signature: p256::ecdsa::Signature = signing_key.sign(input);
                Ok(signature.to_vec())
            }
            Key::Es384(signing_key) => {
                let signature: p384::ecdsa::Signature = signing_key.sign(input);
                Ok(signature.to_vec())
            }
            Key::Rs256(signing_key) => Ok(signing_key.sign(input).to_vec()),
            Key::Rs384(signing_key) => Ok(signing_key.sign(input).to_vec()),
            Key::Rs512(signing_key) => Ok(signing_key.sign(input).to_vec()),
            Key::Ps256(signing_key) => {
                use rsa::signature::RandomizedSigner;
                Ok(signing_key.sign_with_rng(&mut rand::rng(), input).to_vec())
            }
            Key::Ps384(signing_key) => {
                use rsa::signature::RandomizedSigner;
                Ok(signing_key.sign_with_rng(&mut rand::rng(), input).to_vec())
            }
            Key::Ps512(signing_key) => {
                use rsa::signature::RandomizedSigner;
                Ok(signing_key.sign_with_rng(&mut rand::rng(), input).to_vec())
            }
            Key::Ed25519 { key, .. } => Ok(key.sign(input).to_vec()),
        }
    }
}

impl HasPublicKey for PrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.inner.jwk
    }
}
