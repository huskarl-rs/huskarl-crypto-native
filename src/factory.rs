use std::pin::Pin;

use huskarl_core::{
    crypto::verifier::{BoxedJwsVerifier, CreateVerifierError, JwsVerifierPlatform},
    jwk,
    platform::MaybeSendFuture,
};

/// A verifier factory that takes public JWK material and returns a [`BoxedJwsVerifier`].
///
/// The returned verifier is implemented in native rust code.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeVerifierPlatform;

impl JwsVerifierPlatform for NativeVerifierPlatform {
    fn create_verifier_from_jwk(
        &self,
        jwk: jwk::PublicJwk,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<BoxedJwsVerifier, CreateVerifierError>>>> {
        let key = crate::asymmetric::verifier::AsymmetricPublicKey::from_jwk(jwk);

        Box::pin(async {
            key.map_or(Err(CreateVerifierError::UnsupportedKey), |k| {
                Ok(BoxedJwsVerifier::new(k))
            })
        })
    }
}
