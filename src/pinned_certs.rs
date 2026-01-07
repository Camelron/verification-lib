//! Pinned AMD Root Key (ARK) certificates for SEV-SNP verification.
//!
//! These certificates are embedded at compile time and represent the trusted root
//! of the AMD SEV-SNP certificate chain. The ARK certificates are used to verify
//! that an untrusted certificate chain is rooted in AMD's trust hierarchy.

use x509_cert::{der::DecodePem, Certificate};

/// Milan ARK certificate (AMD Root Key for Milan processors)
const MILAN_ARK_PEM: &[u8] = include_bytes!("crypto/test_data/milan_ark.pem");

// TODO: Add Genoa and Turin ARK certificates when available
// const GENOA_ARK_PEM: &[u8] = include_bytes!("crypto/test_data/genoa_ark.pem");
// const TURIN_ARK_PEM: &[u8] = include_bytes!("crypto/test_data/turin_ark.pem");

/// Returns all pinned AMD ARK certificates.
///
/// These certificates are the trusted roots for AMD SEV-SNP verification.
/// Currently includes:
/// - Milan ARK
///
/// Future additions:
/// - Genoa ARK
/// - Turin ARK
pub fn get_pinned_ark_certs() -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let mut certs = Vec::new();

    // Parse Milan ARK
    let milan_ark = Certificate::from_pem(MILAN_ARK_PEM)
        .map_err(|e| format!("Failed to parse Milan ARK certificate: {:?}", e))?;
    certs.push(milan_ark);

    // TODO: Add Genoa and Turin ARKs when available
    // let genoa_ark = Certificate::from_pem(GENOA_ARK_PEM)
    //     .map_err(|e| format!("Failed to parse Genoa ARK certificate: {:?}", e))?;
    // certs.push(genoa_ark);
    //
    // let turin_ark = Certificate::from_pem(TURIN_ARK_PEM)
    //     .map_err(|e| format!("Failed to parse Turin ARK certificate: {:?}", e))?;
    // certs.push(turin_ark);

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_ark_certs_load() {
        let certs = get_pinned_ark_certs().expect("Failed to load pinned ARK certs");
        assert!(!certs.is_empty(), "Should have at least one ARK cert");
    }

    #[test]
    fn test_milan_ark_subject() {
        let certs = get_pinned_ark_certs().expect("Failed to load pinned ARK certs");
        let milan_ark = &certs[0];

        // Verify it's the Milan ARK by checking the subject CN
        let cn = milan_ark
            .tbs_certificate
            .subject
            .to_string();
        assert!(cn.contains("ARK-Milan"), "Expected Milan ARK, got: {}", cn);
    }
}
