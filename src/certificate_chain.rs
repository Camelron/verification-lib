use crate::kds::KdsFetcher;
use crate::AttestationReport;
use log::info;
use std::collections::HashMap;
use x509_cert::{der::Encode, Certificate};
use std::mem::discriminant;

pub struct Chain {
    /// AMD Root Key (ARK) certificate
    pub ark: Certificate,
    /// AMD SEV Key (ASK) certificate
    pub ask: Certificate,
}

/// AMD certificate chain representation for SEV-SNP verification
pub struct AmdCertificates {
    pub chains_cache: Vec<(sev::Generation, Chain)>,
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
        let fetcher = if use_cache {
            KdsFetcher::with_cache()
        } else {
            KdsFetcher::new()
        };

        Ok(Self {
            chains_cache: Vec::new(),
            vcek_cache: HashMap::new(),
            fetcher,
        })
    }

    async fn get_chain(
        &mut self,
        processor_model: sev::Generation,
    ) -> Result<&Chain, Box<dyn std::error::Error>> {
        let existing_indx = self
            .chains_cache
            .iter()
            .position(|(gen, _)| discriminant(gen) == discriminant(&processor_model));

        if let Some(indx) = existing_indx {
            return Ok(&self.chains_cache[indx].1);
        }

        let (ark, ask) = self
            .fetcher
            .fetch_amd_chain(processor_model)
            .await
            .map_err(|e| format!("Error fetching chain: {}", e))?;

        verify_signature(&ark, &ask)?;

        let chain = Chain { ark, ask };

        self.chains_cache.push((processor_model, chain));
        Ok(&self.chains_cache.last().unwrap().1)
    }

    /// Get or fetch the VCEK certificate for a given processor model and attestation report
    pub async fn get_vcek(
        &mut self,
        processor_model: sev::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<&Certificate, Box<dyn std::error::Error>> {
        // Build cache key from processor model and chip_id
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model.titlecase(),
            &attestation_report.chip_id[..8]
        );

        // Check if we already have this VCEK
        if !self.vcek_cache.contains_key(&cache_key) {
            // Fetch the VCEK
            let vcek = self
                .fetcher
                .fetch_amd_vcek(processor_model, attestation_report)
                .await?;

            // Verify that VCEK is signed by ASK
            let chain = self.get_chain(processor_model).await?;
            verify_signature(&chain.ask, &vcek)?;
            info!(
                "VCEK certificate verified successfully for {}",
                processor_model.titlecase()
            );

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
        model: sev::Generation,
    ) -> Result<(Certificate, Certificate), Box<dyn std::error::Error>>;

    /// Fetch VCEK certificate for a given processor model and attestation report
    async fn fetch_amd_vcek(
        &mut self,
        model: sev::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<Certificate, Box<dyn std::error::Error>>;
}

/// Verify that subject is signed by issuer
fn verify_signature(
    issuer: &Certificate,
    subject: &Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    use sev::certs::snp::Certificate as SevCertificate;
    use sev::certs::snp::Verifiable;
    let issuer = SevCertificate::from_der(&issuer.to_der()?)?;
    let subject = SevCertificate::from_der(&subject.to_der()?)?;
    Ok((&issuer, &subject)
        .verify()
        .map_err(|e| format!("Error while verifying signature: {}", e))?)
}
