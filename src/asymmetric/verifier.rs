//! Verifier code for asymmetric keys.

use std::sync::Arc;

use huskarl_core::{
    crypto::verifier::{JwsVerifier, KeyMatch, KeyMatchStrength, VerifyError},
    jwk::{self, KeyOperation, KeyUse},
};
use rsa::{BoxedUint, RsaPublicKey, signature::Verifier};
use snafu::prelude::*;

/// Error type for asymmetric public key verification.
#[derive(Debug, Snafu)]
pub enum AsymmetricPublicKeyError {
    /// The signature is invalid.
    InvalidSignature {
        /// The underlying error.
        source: signature::Error,
    },
    /// The verification failed.
    VerificationFailed {
        /// The underlying error.
        source: signature::Error,
    },
}

impl huskarl_core::Error for AsymmetricPublicKeyError {
    fn is_retryable(&self) -> bool {
        false
    }
}

#[derive(Debug)]
enum Key {
    Es256(p256::ecdsa::VerifyingKey),
    Es384(p384::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
    Rs256(rsa::pkcs1v15::VerifyingKey<sha2::Sha256>),
    Rs384(rsa::pkcs1v15::VerifyingKey<sha2::Sha384>),
    Rs512(rsa::pkcs1v15::VerifyingKey<sha2::Sha512>),
    Ps256(rsa::pss::VerifyingKey<sha2::Sha256>),
    Ps384(rsa::pss::VerifyingKey<sha2::Sha384>),
    Ps512(rsa::pss::VerifyingKey<sha2::Sha512>),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl Key {
    pub fn supported_algorithms(&self) -> &[&str] {
        match self {
            Key::Es256(_) => &["ES256"],
            Key::Es384(_) => &["ES384"],
            Key::Rsa(_) => &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
            Key::Rs256(_) => &["RS256"],
            Key::Rs384(_) => &["RS384"],
            Key::Rs512(_) => &["RS512"],
            Key::Ps256(_) => &["PS256"],
            Key::Ps384(_) => &["PS384"],
            Key::Ps512(_) => &["PS512"],
            Key::Ed25519(_) => &["Ed25519", "EdDSA"],
        }
    }

    pub fn new(jwk_key: jwk::PublicKey, alg: Option<&str>) -> Option<Key> {
        fn rsa_key_from_jwk(rsa_jwk: jwk::RsaPublicKey) -> Option<rsa::RsaPublicKey> {
            let n_boxed = BoxedUint::from_be_slice_vartime(&rsa_jwk.n.into_boxed_slice());
            let e_boxed = BoxedUint::from_be_slice_vartime(&rsa_jwk.e.into_boxed_slice());
            RsaPublicKey::new(n_boxed, e_boxed).ok()
        }

        match jwk_key {
            jwk::PublicKey::Rsa(rsa_public_key) if alg.is_none() => {
                rsa_key_from_jwk(rsa_public_key).map(Self::Rsa)
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("RS256") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Rs256(rsa::pkcs1v15::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("RS384") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Rs384(rsa::pkcs1v15::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("RS512") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Rs512(rsa::pkcs1v15::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("PS256") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Ps256(rsa::pss::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("PS384") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Ps384(rsa::pss::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Rsa(rsa_public_key) if alg == Some("PS512") => {
                rsa_key_from_jwk(rsa_public_key)
                    .map(|k| Self::Ps512(rsa::pss::VerifyingKey::new(k)))
            }
            jwk::PublicKey::Ec(ec_public_key)
                if alg.is_none_or(|a| a == "ES256") && ec_public_key.crv == "P-256" =>
            {
                let mut point =
                    Vec::with_capacity(1 + ec_public_key.x.len() + ec_public_key.y.len());
                point.push(0x04);
                point.extend_from_slice(&ec_public_key.x);
                point.extend_from_slice(&ec_public_key.y);

                p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .ok()
                    .map(Self::Es256)
            }
            jwk::PublicKey::Ec(ec_public_key)
                if alg.is_none_or(|a| a == "ES384") && ec_public_key.crv == "P-384" =>
            {
                let mut point =
                    Vec::with_capacity(1 + ec_public_key.x.len() + ec_public_key.y.len());
                point.push(0x04);
                point.extend_from_slice(&ec_public_key.x);
                point.extend_from_slice(&ec_public_key.y);

                p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .ok()
                    .map(Self::Es384)
            }
            jwk::PublicKey::Okp(okp_public_key)
                if alg.is_none_or(|a| ["Ed25519", "EdDSA"].contains(&a))
                    && okp_public_key.crv == "Ed25519" =>
            {
                ed25519_dalek::VerifyingKey::from_bytes(
                    okp_public_key.x.as_slice().try_into().ok()?,
                )
                .ok()
                .map(Self::Ed25519)
            }
            jwk::PublicKey::Rsa(_)
            | jwk::PublicKey::Ec(_)
            | jwk::PublicKey::Okp(_)
            | jwk::PublicKey::UnknownOrPrivate => None,
        }
    }
}

#[derive(Debug)]
struct AsymmetricPublicKeyInner {
    verifying_key: Key,
    kid: Option<String>,
}

/// An asymmetric public key.
#[derive(Debug, Clone)]
pub struct AsymmetricPublicKey {
    inner: Arc<AsymmetricPublicKeyInner>,
}

impl AsymmetricPublicKey {
    /// Creates an asymmetric public key from a JWK.
    #[must_use]
    pub fn from_jwk(key: jwk::PublicJwk) -> Option<Self> {
        let kid = key.kid;

        if let Some(r#use) = key.key_use
            && r#use != KeyUse::Sign
        {
            return None;
        }

        if let Some(key_ops) = &key.key_operations
            && !key_ops.contains(&KeyOperation::Verify)
        {
            return None;
        }

        let verifying_key = Key::new(key.key, key.algorithm.as_deref());

        verifying_key.map(|k| Self {
            inner: Arc::new(AsymmetricPublicKeyInner {
                verifying_key: k,
                kid,
            }),
        })
    }
}

impl JwsVerifier for AsymmetricPublicKey {
    type Error = AsymmetricPublicKeyError;

    fn key_match(&self, key_match: &KeyMatch<'_>) -> Option<KeyMatchStrength> {
        if !require_alg(
            key_match.alg,
            self.inner.verifying_key.supported_algorithms(),
        ) {
            return None;
        }

        let mut identified = false;

        if let Some(requested_kid) = &key_match.kid {
            match &self.inner.kid {
                Some(k) if k != requested_kid => return None,
                Some(_) => identified = true,
                None => {}
            }
        }

        if identified {
            Some(KeyMatchStrength::ByKeyId)
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

        Ok(match &self.inner.verifying_key {
            Key::Es256(verifying_key) => verifying_key.verify(
                input,
                &p256::ecdsa::Signature::from_slice(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Es384(verifying_key) => verifying_key.verify(
                input,
                &p384::ecdsa::Signature::from_slice(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Rsa(public_key) => match key_match.alg {
                "RS256" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key.clone())
                    .verify(
                        input,
                        &rsa::pkcs1v15::Signature::try_from(signature)
                            .context(InvalidSignatureSnafu)?,
                    ),
                "RS384" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(public_key.clone())
                    .verify(
                        input,
                        &rsa::pkcs1v15::Signature::try_from(signature)
                            .context(InvalidSignatureSnafu)?,
                    ),
                "RS512" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public_key.clone())
                    .verify(
                        input,
                        &rsa::pkcs1v15::Signature::try_from(signature)
                            .context(InvalidSignatureSnafu)?,
                    ),
                "PS256" => rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key.clone()).verify(
                    input,
                    &rsa::pss::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
                ),
                "PS384" => rsa::pss::VerifyingKey::<sha2::Sha384>::new(public_key.clone()).verify(
                    input,
                    &rsa::pss::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
                ),
                "PS512" => rsa::pss::VerifyingKey::<sha2::Sha512>::new(public_key.clone()).verify(
                    input,
                    &rsa::pss::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
                ),
                _ => {
                    unreachable!("RSA algorithm is already checked")
                }
            },
            Key::Rs256(verifying_key) => verifying_key.verify(
                input,
                &rsa::pkcs1v15::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Rs384(verifying_key) => verifying_key.verify(
                input,
                &rsa::pkcs1v15::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Rs512(verifying_key) => verifying_key.verify(
                input,
                &rsa::pkcs1v15::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Ps256(verifying_key) => verifying_key.verify(
                input,
                &rsa::pss::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Ps384(verifying_key) => verifying_key.verify(
                input,
                &rsa::pss::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Ps512(verifying_key) => verifying_key.verify(
                input,
                &rsa::pss::Signature::try_from(signature).context(InvalidSignatureSnafu)?,
            ),
            Key::Ed25519(verifying_key) => verifying_key.verify_strict(
                input,
                &ed25519_dalek::Signature::from_slice(signature).context(InvalidSignatureSnafu)?,
            ),
        }
        .context(VerificationFailedSnafu)?)
    }
}

fn require_alg(requested: &str, supported: &[&str]) -> bool {
    supported.contains(&requested)
}

#[cfg(test)]
mod tests {
    use crate::asymmetric::{
        signer::{GenerateAlgorithm, PrivateKey},
        verifier::AsymmetricPublicKey,
    };
    use huskarl_core::{
        crypto::{
            signer::{AsymmetricJwsSigner, AsymmetricJwsSignerSelector},
            verifier::BoxedJwsVerifier,
        },
        jwt::Jwt,
        token::validator::{ClaimCheck, JwtValidator},
    };
    use serde::{Deserialize, Serialize};

    #[tokio::test]
    async fn verify_access_token() {
        #[derive(Clone, Serialize, Deserialize)]
        struct MyClaims {
            earnest_id: String,
        }

        let signing_key = PrivateKey::generate(GenerateAlgorithm::EdDsa);
        let selected_key = signing_key.select_asymmetric_signer();

        let jwt = Jwt::builder()
            .issuer("https://as.example.com")
            .audience("my-api")
            .issued_now_expires_after(std::time::Duration::from_secs(300))
            .extra_claims(MyClaims {
                earnest_id: "abc123".to_string(),
            })
            .build();
        let token = jwt.to_jws_compact(&selected_key).await.unwrap();

        let public_key =
            AsymmetricPublicKey::from_jwk(selected_key.public_key_jwk().into_owned()).unwrap();

        let validator = JwtValidator::builder()
            .verifier(BoxedJwsVerifier::new(public_key))
            .aud(ClaimCheck::required_value("my-api"))
            .build();

        let validated = validator
            .validate::<serde_json::Value>(token.expose_secret())
            .await
            .unwrap();

        assert_eq!(validated.issuer.as_deref(), Some("https://as.example.com"));
        assert_eq!(validated.audience, ["my-api"]);
        assert!(validated.expiration.is_some());
    }
}
