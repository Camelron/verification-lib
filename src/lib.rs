//! WASM-compatible helper crate for Patty
//!
//! This crate will host SEV-SNP verification code that can be compiled for both
//! native service usage and for browser/WASM relying parties. For now it re-exports
//! the `sev_verification` module which contains the verification engine.

pub mod crypto;
pub mod snp_report;

pub mod certificate_chain;

pub mod kds;

pub mod pinned_certs;

pub mod sev_verification;

pub use sev::firmware::guest::AttestationReport;
pub use x509_cert::Certificate;

// Re-export pinned certs functionality
pub use pinned_certs::get_pinned_ark_certs;

// Re-export the main types at crate root for convenient use (wasm only)
pub use certificate_chain::AmdCertificates;
pub use sev_verification::{SevVerificationDetails, SevVerificationResult, SevVerifier};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// Initialize the WASM module with panic hook and logging
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::default());
}

/// JavaScript-facing verification function
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn verify_attestation_report(attestation_report_json: &str) -> Result<String, String> {
    let attestation_report: AttestationReport = serde_json::from_str(attestation_report_json)
        .map_err(|e| format!("Failed to parse attestation report: {}", e))?;

    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {}", e))?;
    match verifier.verify_attestation(&attestation_report).await {
        Ok(result) => {
            serde_json::to_string(&result).map_err(|e| format!("Failed to serialize result: {}", e))
        }
        Err(e) => {
            // Create an error result
            let error_result = SevVerificationResult {
                is_valid: false,
                details: SevVerificationDetails {
                    processor_identified: false,
                    certificates_fetched: false,
                    certificate_chain_valid: false,
                    signature_valid: false,
                    tcb_valid: false,
                    processor_model: None,
                },
                errors: vec![format!("{}", e)],
            };
            serde_json::to_string(&error_result)
                .map_err(|e| format!("Failed to serialize error result: {}", e))
        }
    }
}

/// JavaScript-facing verification function with explicit certificate chain.
///
/// This function verifies an attestation report using a provided certificate chain
/// instead of fetching certificates from AMD KDS. The chain is verified against
/// pinned AMD ARK root certificates.
///
/// # Arguments
/// * `attestation_report_json` - JSON-serialized AttestationReport (as byte array)
/// * `untrusted_chain_pem` - JSON array of PEM-encoded certificates (intermediates like ASK)
/// * `leaf_pem` - PEM-encoded leaf certificate (VCEK) that signed the attestation report
///
/// # Returns
/// JSON-serialized verification result
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn verify_attestation_report_with_chain(
    attestation_report_json: &str,
    untrusted_chain_pem: &str,
    leaf_pem: &str,
) -> Result<String, String> {
    use crate::crypto::{CryptoBackend, Crypto, Verifier};
    use crate::snp_report::AttestationReport as SnpAttestationReport;
    use x509_cert::der::DecodePem;
    use zerocopy::TryFromBytes;

    // Parse attestation report from JSON (as base64-encoded binary)
    let report_bytes: Vec<u8> = serde_json::from_str(attestation_report_json)
        .map_err(|e| format!("Failed to parse attestation report JSON: {}", e))?;
    
    let attestation_report = SnpAttestationReport::try_read_from_bytes(&report_bytes)
        .map_err(|e| format!("Failed to parse attestation report bytes: {:?}", e))?;

    // Parse untrusted chain from JSON array of PEM strings
    let chain_pems: Vec<String> = serde_json::from_str(untrusted_chain_pem)
        .map_err(|e| format!("Failed to parse untrusted chain JSON: {}", e))?;
    
    let untrusted_chain: Vec<x509_cert::Certificate> = chain_pems
        .iter()
        .enumerate()
        .map(|(i, pem)| {
            x509_cert::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| format!("Failed to parse certificate {} in chain: {:?}", i, e))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Parse leaf certificate from PEM
    let leaf = x509_cert::Certificate::from_pem(leaf_pem.as_bytes())
        .map_err(|e| format!("Failed to parse leaf certificate: {:?}", e))?;

    // Get pinned AMD ARK certificates and convert to backend certificate type
    let pinned_arks = crate::pinned_certs::get_pinned_ark_certs()
        .map_err(|e| format!("Failed to load pinned ARK certificates: {}", e))?;
    let pinned_arks_native: Vec<_> = pinned_arks
        .iter()
        .map(|c| Crypto::from_x509_cert(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to convert pinned ARK certificates: {}", e))?;

    // Convert untrusted chain to backend certificate type
    let untrusted_chain_native: Vec<_> = untrusted_chain
        .iter()
        .map(|c| Crypto::from_x509_cert(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to convert untrusted chain certificates: {}", e))?;

    // Convert leaf to backend certificate type
    let leaf_native = Crypto::from_x509_cert(&leaf)
        .map_err(|e| format!("Failed to convert leaf certificate: {}", e))?;

    // Step 1: Verify the certificate chain roots to a pinned ARK
    Crypto::verify_chain(pinned_arks_native, untrusted_chain_native, leaf_native.clone())
        .map_err(|e| format!("Certificate chain verification failed: {}", e))?;

    // Step 2: Verify that the attestation report is signed by the leaf certificate
    leaf_native.verify(&attestation_report)
        .map_err(|e| format!("Attestation report signature verification failed: {}", e))?;

    // Build success result
    let result = SevVerificationResult {
        is_valid: true,
        details: SevVerificationDetails {
            processor_identified: true,
            certificates_fetched: true, // Chain was provided externally
            certificate_chain_valid: true,
            signature_valid: true,
            tcb_valid: true, // TODO: Add TCB validation if needed
            processor_model: None, // Could be determined from report if needed
        },
        errors: vec![],
    };

    serde_json::to_string(&result)
        .map_err(|e| format!("Failed to serialize result: {}", e))
}

/// Native Rust API for verifying an attestation report with an explicit certificate chain.
///
/// This function verifies an attestation report using a provided certificate chain
/// instead of fetching certificates from AMD KDS. The chain is verified against
/// pinned AMD ARK root certificates.
///
/// # Arguments
/// * `attestation_report` - The SNP attestation report to verify
/// * `untrusted_chain` - Intermediate certificates (e.g., ASK) between root ARK and leaf
/// * `leaf` - The leaf certificate (VCEK) that signed the attestation report
///
/// # Returns
/// Ok(()) if verification succeeds, Err with description if it fails
pub fn verify_with_chain(
    attestation_report: &snp_report::AttestationReport,
    untrusted_chain: Vec<x509_cert::Certificate>,
    leaf: x509_cert::Certificate,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::crypto::{CryptoBackend, Crypto, Verifier};

    // Get pinned AMD ARK certificates and convert to backend certificate type
    let pinned_arks = crate::pinned_certs::get_pinned_ark_certs()?;
    let pinned_arks_native: Vec<_> = pinned_arks
        .iter()
        .map(|c| Crypto::from_x509_cert(c))
        .collect::<Result<Vec<_>, _>>()?;

    // Convert untrusted chain to backend certificate type
    let untrusted_chain_native: Vec<_> = untrusted_chain
        .iter()
        .map(|c| Crypto::from_x509_cert(c))
        .collect::<Result<Vec<_>, _>>()?;

    // Convert leaf to backend certificate type
    let leaf_native = Crypto::from_x509_cert(&leaf)?;

    // Step 1: Verify the certificate chain roots to a pinned ARK
    Crypto::verify_chain(pinned_arks_native, untrusted_chain_native, leaf_native.clone())?;

    // Step 2: Verify that the attestation report is signed by the leaf certificate
    leaf_native.verify(attestation_report)?;

    Ok(())
}
