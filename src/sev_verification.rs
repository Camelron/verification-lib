//! WASM-only AMD SEV-SNP Attestation Verification
//!
//! This implementation is designed to be compiled only for wasm32 and uses
//! wasm-bindgen for fetching KDS artifacts via an extension-provided JS bridge.
use crate::AttestationReport;
use crate::certificate_chain::AmdCertificates;

use asn1_rs::{oid, Oid};
use log::{error, info};
#[cfg(target_arch = "wasm32")]
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
#[cfg(target_arch = "wasm32")]
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use x509_cert::Certificate;

/// Result of AMD SEV-SNP attestation verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SevVerificationResult {
    /// Whether the attestation passed all verification checks
    pub is_valid: bool,
    /// Detailed verification status for each component
    pub details: SevVerificationDetails,
    /// Error messages if verification failed
    pub errors: Vec<String>,
}

/// Detailed verification results for AMD SEV-SNP attestation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SevVerificationDetails {
    /// Whether the processor model was identified successfully
    pub processor_identified: bool,
    /// Whether AMD certificates were fetched successfully  
    pub certificates_fetched: bool,
    /// Whether the certificate chain is valid (ARK -> ASK -> VCEK)
    pub certificate_chain_valid: bool,
    /// Whether the attestation signature is valid
    pub signature_valid: bool,
    /// Whether TCB values match certificate extensions
    pub tcb_valid: bool,
    /// Processor model identified from the attestation report
    pub processor_model: Option<String>,
}

/// SEV-SNP OID extensions for VCEK certificate verification
/// These OIDs are used to extract TCB values from X.509 certificate extensions
enum SnpOid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
    Fmc,
}

impl SnpOid {
    fn oid(&self) -> Oid<'_> {
        match self {
            SnpOid::BootLoader => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1),
            SnpOid::Tee => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2),
            SnpOid::Snp => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3),
            SnpOid::Ucode => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8),
            SnpOid::HwId => oid!(1.3.6 .1 .4 .1 .3704 .1 .4),
            SnpOid::Fmc => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .9),
        }
    }
}

/// WASM SEV verifier (only compiled for wasm32)
pub struct SevVerifier {
    amd_certificates: AmdCertificates,
}

impl SevVerifier {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_arch = "wasm32")]
        Self::init_wasm_logging();
        let amd_certificates = AmdCertificates::new().await?;
        Ok(Self {
            amd_certificates,
        })
    }

    pub async fn with_cache() -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_arch = "wasm32")]
        Self::init_wasm_logging();
        let amd_certificates = AmdCertificates::with_cache(true).await?;
        Ok(Self {
            amd_certificates,
        })
    }

    #[cfg(target_arch = "wasm32")]
    /// Initialize wasm logging and panic hook once. Only available when the
    /// `wasm` feature is enabled. No-op on non-wasm builds or when the feature
    /// isn't enabled.
    fn init_wasm_logging() {
        {
            static INIT: std::sync::Once = std::sync::Once::new();
            INIT.call_once(|| {
                // Route panics to console.error
                console_error_panic_hook::set_once();
                // Initialize the wasm logger to forward `log` records to console.log
                wasm_logger::init(wasm_logger::Config::new(log::Level::Info));
            });
        }
    }

    // Shared helper: derive processor_model from report
    pub fn get_processor_model(
        &self,
        attestation_report: &AttestationReport,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if attestation_report.version < 3 {
            if attestation_report.chip_id.iter().all(|&b| b == 0) {
                return Err("Attestation report version <3 and chip id is all zeroes".into());
            } else {
                if attestation_report.chip_id.len() >= 64
                    && attestation_report.chip_id[8..64].iter().all(|&b| b == 0)
                {
                    return Ok("Turin".to_string());
                }
                return Err("Attestation report ambiguous for pre-3 versions".into());
            }
        }

        let cpu_fam = attestation_report
            .cpuid_fam_id
            .ok_or("Missing CPU family ID")?;
        let cpu_mod = attestation_report
            .cpuid_mod_id
            .ok_or("Missing CPU model ID")?;
        let processor_model = match cpu_fam {
            0x19 => match cpu_mod {
                0x0..=0xF => "Milan",
                0x10..=0x1F | 0xA0..=0xAF => "Genoa",
                _ => return Err("Processor model not supported".into()),
            },
            0x1A => match cpu_mod {
                0x0..=0x11 => "Turin",
                _ => return Err("Processor model not supported".into()),
            },
            _ => return Err("Processor family not supported".into()),
        };
        Ok(processor_model.to_string())
    }

    pub async fn verify_attestation(
        &mut self,
        attestation_report: &AttestationReport,
    ) -> Result<SevVerificationResult, Box<dyn std::error::Error>> {
        let mut result = SevVerificationResult {
            is_valid: false,
            details: SevVerificationDetails {
                processor_identified: false,
                certificates_fetched: false,
                certificate_chain_valid: false,
                signature_valid: false,
                tcb_valid: false,
                processor_model: None,
            },
            errors: Vec::new(),
        };

        // Step 1: Identify processor model
        match self.get_processor_model(attestation_report) {
            Ok(model) => {
                result.details.processor_identified = true;
                result.details.processor_model = Some(model.clone());
                info!("Identified processor model: {}", model);
            }
            Err(e) => {
                let error = format!("Failed to identify processor model: {}", e);
                result.errors.push(error.clone());
                error!("{}", error);
                return Ok(result);
            }
        }

        let processor_model = result.details.processor_model.as_ref().unwrap();

        // Step 2: Get VCEK certificate for this processor (includes chain verification)
        let vcek = match self
            .amd_certificates
            .get_vcek(&processor_model, attestation_report)
            .await
        {
            Ok(cert) => {
                result.details.certificates_fetched = true;
                result.details.certificate_chain_valid = true;
                info!("VCEK certificate fetched and verified successfully");
                cert
            }
            Err(e) => {
                let msg = format!("Failed to fetch/verify VCEK certificate: {}", e);
                result.errors.push(msg.clone());
                error!("{}", msg);
                return Ok(result);
            }
        };

        // Step 3: Verify attestation signature
        if let Err(e) = Self::verify_attestation_signature(attestation_report, &vcek) {
            let msg = format!("Signature verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(result);
        }
        result.details.signature_valid = true;

        // Step 4: Verify TCB values
        if let Err(e) = Self::verify_tcb_values(&vcek, attestation_report) {
            let msg = format!("TCB verification failed: {}", e);
            result.errors.push(msg.clone());
            error!("{}", msg);
            return Ok(result);
        }
        result.details.tcb_valid = true;

        result.is_valid = true;
        if result.is_valid {
            info!("AMD SEV-SNP verification PASSED");
        } else {
            error!("AMD SEV-SNP verification FAILED: {:?}", result.errors);
        }
        Ok(result)
    }

    #[cfg(target_arch = "wasm32")]
    fn verify_attestation_signature(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Extract VCEK public key (SEC1-encoded)
        let vcek_pub = vcek
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();

        // Serialize the signature to get its byte representation
        // The sev signature is 144 bytes: 72 bytes R + 72 bytes S
        let sig_serialized = serde_json::to_vec(&attestation_report.signature)
            .map_err(|e| format!("Failed to serialize signature: {:?}", e))?;
        
        // Parse as a P384 signature - try both DER and raw slice formats
        let signature = Signature::from_der(&sig_serialized)
            .or_else(|_| Signature::from_slice(&sig_serialized))
            .map_err(|e| format!("Failed to parse signature: {:?}", e))?;

        // 1) Construct the canonical report bytes and extract the signed region
        let mut report_bytes: Vec<u8> = Vec::new();
        attestation_report.write_bytes(&mut report_bytes)?;
        let signed_bytes = &report_bytes[0x0..0x2A0];

        // 2) Create hash digest
        let mut hasher = Sha384::new();
        hasher.update(signed_bytes);
        let digest = hasher.finalize();

        // 3) Verify signature using p384 verifying key derived from VCEK
        let vk = VerifyingKey::from_sec1_bytes(&vcek_pub)
            .map_err(|e| format!("Failed to parse VCEK public key: {:?}", e))?;
        vk.verify(&digest, &signature)
            .map_err(|_| "VEK did NOT sign the Attestation Report!")?;
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn verify_attestation_signature(
        attestation_report: &AttestationReport,
        vcek: &Certificate,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use openssl::ecdsa::EcdsaSig;
        use openssl::bn::BigNum;
        use openssl::x509::X509;
        use openssl::hash::{hash, MessageDigest};
        use x509_cert::der::Encode;

        let vcek_x509 = {
            X509::from_der(&vcek.to_der()?)
        }.map_err(|e| format!("Failed to parse VCEK certificate: {:?}", e))?;

        let ec_key = {
            vcek_x509.public_key()?.ec_key()
        }.map_err(|e| format!("Failed to get EC key from VCEK public key: {:?}", e))?;
        ec_key.check_key().map_err(|e| format!("Invalid EC key: {:?}", e))?;

        // Get signature components (R and S) from attestation report
        // from_slice uses BN_bin2bn rather than BN_lebin2bn 
        let mut r_bytes = attestation_report.signature.r().clone();
        r_bytes.reverse();
        let r = BigNum::from_slice(&r_bytes)
            .map_err(|e| format!("Failed to create BigNum from R: {:?}", e))?;
        let mut s_bytes = attestation_report.signature.s().clone();
        s_bytes.reverse();
        let s = BigNum::from_slice(&s_bytes)
            .map_err(|e| format!("Failed to create BigNum from S: {:?}", e))?;

        // Create ECDSA signature from R and S
        let ecdsa_sig = EcdsaSig::from_private_components(r, s)
            .map_err(|e| format!("Failed to create ECDSA signature: {:?}", e))?;

        // Construct the canonical report bytes and extract the signed region
        let mut report_bytes: Vec<u8> = Vec::new();
        attestation_report.write_bytes(&mut report_bytes)?;
        let report_without_sig = &report_bytes[0..0x29F+1];

        let digest = hash(MessageDigest::sha384(), report_without_sig)
            .map_err(|e| format!("Failed to compute SHA-384 hash: {:?}", e))?;

        // Verify signature directly using EC key
        let valid = ecdsa_sig.verify(&digest, &ec_key)
            .map_err(|e| format!("Signature verification error: {:?}", e))?;

        if !valid {
            return Err("VCEK did NOT sign the Attestation Report!".into());
        }

        Ok(())
    }

    fn verify_tcb_values(
        vcek: &Certificate,
        attestation_report: &AttestationReport,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get extensions from VCEK certificate
        let extensions = vcek
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or("VCEK certificate has no extensions")?;

        // Build a HashMap of OID -> extension value for easy lookup
        let mut ext_map: HashMap<String, &[u8]> = HashMap::new();
        for ext in extensions.iter() {
            let oid_str = ext.extn_id.to_string();
            ext_map.insert(oid_str, ext.extn_value.as_bytes());
        }

        // Helper to check extension value (handles different ASN.1 wrapping)
        let check_ext = |ext_value: &[u8], expected: &[u8]| -> bool {
            // Try direct match
            if ext_value == expected {
                return true;
            }
            // Try with INTEGER tag (0x02) wrapper
            if ext_value.len() >= 2 && ext_value[0] == 0x02 {
                if let Some(&last) = ext_value.last() {
                    if expected.len() == 1 && last == expected[0] {
                        return true;
                    }
                }
            }
            // Try with OCTET STRING tag (0x04) wrapper
            if ext_value.len() >= 2 && ext_value[0] == 0x04 && ext_value.len() >= 2 {
                return &ext_value[2..] == expected;
            }
            false
        };

        let bl_oid = SnpOid::BootLoader.oid().to_string();
        if let Some(&cert_bl) = ext_map.get(&bl_oid) {
            if !check_ext(cert_bl, &attestation_report.reported_tcb.bootloader.to_le_bytes()) {
                return Err("Report TCB Boot Loader and Certificate Boot Loader mismatch".into());
            }
        }

        let tee_oid = SnpOid::Tee.oid().to_string();
        if let Some(&cert_tee) = ext_map.get(&tee_oid) {
            if !check_ext(cert_tee, &attestation_report.reported_tcb.tee.to_le_bytes()) {
                return Err("Report TCB TEE and Certificate TEE mismatch".into());
            }
        }

        let snp_oid = SnpOid::Snp.oid().to_string();
        if let Some(&cert_snp) = ext_map.get(&snp_oid) {
            if !check_ext(cert_snp, &attestation_report.reported_tcb.snp.to_le_bytes()) {
                return Err("Report TCB SNP and Certificate SNP mismatch".into());
            }
        }

        let ucode_oid = SnpOid::Ucode.oid().to_string();
        if let Some(&cert_ucode) = ext_map.get(&ucode_oid) {
            if !check_ext(
                cert_ucode,
                &attestation_report.reported_tcb.microcode.to_le_bytes(),
            ) {
                return Err("Report TCB Microcode and Certificate Microcode mismatch".into());
            }
        }

        let hwid_oid = SnpOid::HwId.oid().to_string();
        if let Some(&cert_hwid) = ext_map.get(&hwid_oid) {
            if !check_ext(cert_hwid, attestation_report.chip_id.as_slice()) {
                return Err("Report TCB ID and Certificate ID mismatch".into());
            }
        }

        Ok(())
    }
}
