use x509_cert::{Certificate, der::Encode};
#[cfg(target_arch = "wasm32")]
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use crate::AttestationReport;
use crate::kds::KdsFetcher;
use log::info;
use std::collections::HashMap;

/// AMD certificate chain representation for SEV-SNP verification
pub struct AmdCertificates {
    /// AMD Root Key (ARK) certificate
    pub ark: Certificate,
    /// AMD SEV Key (ASK) certificate
    pub ask: Certificate,
    /// Versioned Chip Endorsement Key (VCEK) certificates by processor model
    vcek_cache: HashMap<String, Certificate>,
    /// Certificate fetcher
    fetcher: KdsFetcher,
}

impl AmdCertificates {
    /// Create a new AmdCertificates by fetching ARK and ASK from KDS
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_cache(false).await
    }

    /// Create a new AmdCertificates with caching enabled
    pub async fn with_cache(use_cache: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Create fetcher
        let mut fetcher = if use_cache {
            KdsFetcher::with_cache()
        } else {
            KdsFetcher::new()
        };

        // Fetch ARK and ASK
        let (ark, ask) = fetcher.fetch_amd_chain().await?;

        // Verify that ASK is signed by ARK
        verify_signature(&ark, &ask)?;
        // Verify that ARK is self-signed
        verify_signature(&ark, &ark)?;
        info!("AMD certificate chain (ARK/ASK) verified successfully");

        Ok(Self {
            ark,
            ask,
            vcek_cache: HashMap::new(),
            fetcher,
        })
    }

    /// Get or fetch the VCEK certificate for a given processor model and attestation report
    pub async fn get_vcek(
        &mut self,
        processor_model: &str,
        attestation_report: &AttestationReport,
    ) -> Result<&Certificate, Box<dyn std::error::Error>> {
        // Build cache key from processor model and chip_id
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );

        // Check if we already have this VCEK
        if !self.vcek_cache.contains_key(&cache_key) {
            // Fetch the VCEK
            let vcek = self.fetcher
                .fetch_amd_vcek(processor_model, attestation_report)
                .await?;

            // Verify that VCEK is signed by ASK
            verify_signature(&self.ask, &vcek)?;
            info!("VCEK certificate verified successfully for {}", processor_model);

            // Store in cache
            self.vcek_cache.insert(cache_key.clone(), vcek);
        }

        // Return reference to cached VCEK
        Ok(self.vcek_cache.get(&cache_key).unwrap())
    }

    /// Check if a VCEK is already cached for the given processor model
    pub fn has_vcek(&self, processor_model: &str, attestation_report: &AttestationReport) -> bool {
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );
        self.vcek_cache.contains_key(&cache_key)
    }
}

/// Trait for fetching AMD certificates from a certificate source
pub(crate) trait CertificateFetcher {
    /// Fetch AMD certificate chain (ARK and ASK)
    async fn fetch_amd_chain(
        &mut self,
    ) -> Result<(Certificate, Certificate), Box<dyn std::error::Error>>;

    /// Fetch VCEK certificate for a given processor model and attestation report
    async fn fetch_amd_vcek(
        &mut self,
        processor_model: &str,
        attestation_report: &AttestationReport,
    ) -> Result<Certificate, Box<dyn std::error::Error>>;
}

#[cfg(target_arch = "wasm32")]
/// Verify that subject is signed by issuer
fn verify_signature(
    issuer: &Certificate,
    subject: &Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    // Extract public key from issuer certificate
    let issuer_pub = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    // Get TBS (to-be-signed) certificate bytes from subject
    let subject_tbs = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| format!("Failed to encode TBS certificate: {:?}", e))?;

    // Extract signature bytes from subject certificate
    let sig_bytes = subject.signature.raw_bytes();

    let vk = VerifyingKey::from_sec1_bytes(issuer_pub)
        .map_err(|e| format!("Failed to parse issuer public key: {:?}", e))?;
    let sig = Signature::from_der(sig_bytes)
        .map_err(|e| format!("Failed to parse signature DER: {:?}", e))?;

    // Use p384's signature verification
    vk.verify(&subject_tbs, &sig)
        .map_err(|e| format!("Signature verification failed: {:?}", e))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
/// Verify that subject is signed by issuer using OpenSSL
fn verify_signature(
    issuer: &Certificate,
    subject: &Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    use openssl::x509::X509;
    use openssl::pkey::PKey;

    // Convert issuer certificate to DER and parse with OpenSSL
    let issuer_der = issuer
        .to_der()
        .map_err(|e| format!("Failed to encode issuer certificate to DER: {:?}", e))?;
    let issuer_x509 = X509::from_der(&issuer_der)
        .map_err(|e| format!("Failed to parse issuer certificate with OpenSSL: {:?}", e))?;

    // Extract public key from issuer
    let issuer_pubkey: PKey<openssl::pkey::Public> = issuer_x509.public_key()
        .map_err(|e| format!("Failed to extract issuer public key: {:?}", e))?;

    // Convert subject certificate to DER and parse with OpenSSL
    let subject_der = subject
        .to_der()
        .map_err(|e| format!("Failed to encode subject certificate to DER: {:?}", e))?;
    let subject_x509 = X509::from_der(&subject_der)
        .map_err(|e| format!("Failed to parse subject certificate with OpenSSL: {:?}", e))?;

    // Verify the subject's signature using issuer's public key
    let valid = subject_x509
        .verify(&issuer_pubkey)
        .map_err(|e| format!("Signature verification error: {:?}", e))?;

    if !valid {
        return Err("Signature verification failed: subject not signed by issuer".into());
    }

    Ok(())
}