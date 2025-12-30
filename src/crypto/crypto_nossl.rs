use std::vec;

use p384::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use rsa::{
    pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    RsaPublicKey,
};
use sha2::Sha384;
use x509_cert::der::{referenced::OwnedToRef, Decode, DecodePem, Encode};
use zerocopy::IntoBytes;

use super::super::snp_report::{AttestationReport, Signature};
use super::{CryptoBackend, Result, Verifier};

pub struct Crypto;

type Certificate = x509_cert::Certificate;

mod oid {
    use x509_cert::der::oid::ObjectIdentifier;

    // RSA-PSS (1.2.840.113549.1.1.10)
    pub const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    // ECDSA with SHA-384 (1.2.840.10045.4.3.3)
    pub const ECDSA_WITH_SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
}

impl Verifier<Certificate> for Certificate {
    fn verify(&self, subject: &Certificate) -> Result<()> {
        // Encode the TBS (to-be-signed) portion of the subject certificate
        let tbs_bytes = subject
            .tbs_certificate
            .to_der()
            .map_err(|e| format!("Failed to encode TBS certificate: {:?}", e))?;

        let sig_bytes = subject.signature.raw_bytes();
        let sig_algo_oid = &subject.signature_algorithm.oid;
        let issuer_spki = &self.tbs_certificate.subject_public_key_info;

        if *sig_algo_oid == oid::RSA_PSS {
            // RSA-PSS with SHA-384
            use rsa::signature::Verifier;

            let rsa_pub = RsaPublicKey::try_from(issuer_spki.owned_to_ref())
                .map_err(|e| format!("Failed to parse RSA public key: {:?}", e))?;

            let verifying_key = PssVerifyingKey::<Sha384>::new(rsa_pub);

            let sig = PssSignature::try_from(sig_bytes)
                .map_err(|e| format!("Failed to parse RSA-PSS signature: {:?}", e))?;

            verifying_key
                .verify(&tbs_bytes, &sig)
                .map_err(|e| format!("RSA-PSS signature verification failed: {:?}", e))?;

            Ok(())
        } else if *sig_algo_oid == oid::ECDSA_WITH_SHA384 {
            // ECDSA P-384 with SHA-384
            use p384::ecdsa::signature::Verifier;

            let pub_key_bytes = issuer_spki.subject_public_key.raw_bytes();

            let vk = EcdsaVerifyingKey::from_sec1_bytes(pub_key_bytes)
                .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;

            let sig = p384::ecdsa::Signature::from_der(sig_bytes)
                .map_err(|e| format!("Failed to parse ECDSA signature DER: {:?}", e))?;

            vk.verify(&tbs_bytes, &sig)
                .map_err(|e| format!("ECDSA signature verification failed: {:?}", e))?;

            Ok(())
        } else {
            Err(format!("Unsupported signature algorithm OID: {}", sig_algo_oid).into())
        }
    }
}

impl CryptoBackend for Crypto {
    type Certificate = Certificate;
    fn verify_chain(
        trusted_certs: Vec<Certificate>,
        untrusted_chain: Vec<Certificate>,
        leaf: Certificate,
    ) -> Result<()> {
        let untrusted_chain = untrusted_chain.iter().chain(std::iter::once(&leaf));
        let mut prev: Option<&x509_cert::certificate::CertificateInner> = None;
        for cert in untrusted_chain {
            if let Some(issuer) = prev {
                issuer.verify(cert)?;
            } else {
                trusted_certs
                    .iter()
                    .find(|trusted| trusted.verify(cert).is_ok())
                    .ok_or("Failed to verify certificate: no matching trusted issuer")?;
            }
            prev = Some(cert);
        }
        Ok(())
    }
}

fn verify_report_sig_ecdsa_p384_sha384(
    vcek: &Certificate,
    signed_bytes: &[u8],
    signature: Signature,
) -> Result<()> {
    let vcek_pub = vcek
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let vk = EcdsaVerifyingKey::from_sec1_bytes(vcek_pub)
        .map_err(|e| format!("Failed to parse ECDSA public key: {:?}", e))?;

    // P-384 scalars are 48 bytes each, extract from the 72-byte arrays
    let mut r_bytes: [u8; 48] = signature.r[..48]
        .try_into()
        .map_err(|_| "Invalid r scalar length")?;
    r_bytes.reverse();
    let mut s_bytes: [u8; 48] = signature.s[..48]
        .try_into()
        .map_err(|_| "Invalid s scalar length")?;
    s_bytes.reverse();

    let sig = p384::ecdsa::Signature::from_scalars(r_bytes, s_bytes)
        .map_err(|e| format!("Failed to parse ECDSA signature from scalars: {:?}", e))?;

    use p384::ecdsa::signature::Verifier;
    vk.verify(signed_bytes, &sig)
        .map_err(|e| format!("Attestation report signature verification failed: {:?}", e))?;
    Ok(())
}

impl Verifier<AttestationReport> for Certificate {
    fn verify(&self, report: &AttestationReport) -> Result<()> {
        let signed_bytes = report.signed_bytes();
        match report.signature_algo.get() {
            0x0001 => verify_report_sig_ecdsa_p384_sha384(self, signed_bytes, report.signature),
            _ => Err(format!(
                "Unsupported signature algorithm: 0x{:04X}",
                report.signature_algo.get()
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod test {
    use x509_cert::der::DecodePem;
    use zerocopy::TryFromBytes;

    use super::*;

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
    const MILAN_REPORT: &[u8] = include_bytes!("test_data/milan_attestation_report.bin");

    fn cert(pem: &[u8]) -> Certificate {
        Certificate::from_pem(pem).unwrap()
    }

    #[test]
    fn verifier_trait_impl() {
        let ark = cert(MILAN_ARK);
        let ask = cert(MILAN_ASK);

        // Self signed
        ark.verify(&ark).unwrap();
        // Signed by ARK
        ark.verify(&ask).unwrap();
    }

    #[test]
    fn corrupted_verifier_trait_impl() {
        let ark = cert(MILAN_ARK);
        let mut ask = cert(MILAN_ASK);

        // Corrupt a byte in the ASK signature
        let sig_bytes = ask.signature.raw_bytes();
        let mut corrupted_sig = sig_bytes.to_vec();
        corrupted_sig[10] ^= 0xFF; // Flip a bit
        ask.signature = x509_cert::der::asn1::BitString::new(0, corrupted_sig)
            .expect("Failed to create corrupted signature");

        // Verification should fail
        ark.verify(&ask)
            .expect_err("Corrupted ASK signature should not verify");
    }

    #[test]
    fn full_chain_verifies() {
        Crypto::verify_chain(
            vec![cert(MILAN_ARK)],
            vec![cert(MILAN_ASK)],
            cert(MILAN_VCEK),
        )
        .unwrap();
    }

    #[test]
    fn empty_trust_store_fails() {
        Crypto::verify_chain(vec![], vec![], cert(MILAN_VCEK))
            .expect_err("Should fail with no trusted certs");
    }

    #[test]
    fn untrusted_intermediates_are_required() {
        Crypto::verify_chain(vec![cert(MILAN_ARK)], vec![], cert(MILAN_VCEK))
            .expect_err("VCEK should not verify without ASK intermediate");
    }

    #[test]
    fn self_signed_certificates() {
        Crypto::verify_chain(vec![cert(MILAN_ARK)], vec![], cert(MILAN_ARK)).unwrap();
    }

    #[test]
    fn attestation_report_signature_verifies() {
        let vcek = cert(MILAN_VCEK);
        let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();
        vcek.verify(&report).unwrap();
    }

    #[test]
    fn corrupted_report_fails_to_verify() {
        let vcek = cert(MILAN_VCEK);
        let mut report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();

        // Corrupt a byte in the signed portion
        let report_bytes = report.as_mut_bytes();
        report_bytes[100] ^= 0xFF;

        vcek.verify(&report)
            .expect_err("Corrupted report should not verify");
    }
}
