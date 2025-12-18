//! Crypto module for verification-lib.

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use sev::snp::AttestationReport;

/// A trait for verification primitives.
pub trait Verifier<T> {
    fn verify(&self, data: &T) -> Result<()>;
}

pub trait CryptoBackend {
    type Certificate: Verifier<Self::Certificate> + Verifier<AttestationReport>;
}


//mod crypto_nossl;
//#[cfg(feature = "crypto_pure_rust")]
//pub use crypto_nossl::Crypto;

mod crypto_openssl;
#[cfg(feature = "crypto_openssl")]
pub use crypto_openssl::Crypto;
