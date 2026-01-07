//! Crypto module for verification-lib.

#[cfg(not(any(feature = "crypto_openssl", feature = "crypto_pure_rust")))]
compile_error!("Either `crypto_openssl` or `crypto_pure_rust` feature must be enabled.");

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use super::snp_report::AttestationReport;

/// A trait for verification primitives.
pub trait Verifier<T> {
    fn verify(&self, data: &T) -> Result<()>;
}

pub trait CryptoBackend {
    type Certificate: Verifier<Self::Certificate> + Verifier<AttestationReport>;

    fn verify_chain(
        trusted_certs: Vec<Self::Certificate>,
        untrusted_chain: Vec<Self::Certificate>,
        leaf: Self::Certificate,
    ) -> Result<()>;
}

#[cfg(feature = "crypto_pure_rust")]
mod crypto_pure_rust;
#[cfg(feature = "crypto_openssl")]
mod crypto_openssl;

// If pure rust crypto is enabled export it, otherwise export openssl crypto
#[cfg(feature = "crypto_pure_rust")]
pub use crypto_pure_rust::Crypto;
#[cfg(all(feature = "crypto_openssl", not(feature = "crypto_pure_rust")))]
pub use crypto_openssl::Crypto;
