use std::vec;

use openssl::ecdsa::EcdsaSig;
use openssl::stack::Stack;

use super::super::snp_report::{AttestationReport, Signature};
use super::{CryptoBackend, Result, Verifier};

pub struct Crypto;

type Certificate = openssl::x509::X509;

impl CryptoBackend for Crypto {
    type Certificate = Certificate;
    fn verify_chain(
        trusted_certs: Vec<Certificate>,
        untrusted_chain: Vec<Certificate>,
        leaf: Certificate,
    ) -> Result<()> {
        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        for cert in trusted_certs {
            store_builder.add_cert(cert)?;
        }
        let store = store_builder.build();
        let mut ctx = openssl::x509::X509StoreContext::new()?;
        let mut chain = Stack::new()?;
        for cert in untrusted_chain.iter() {
            chain.push(cert.to_owned())?;
        }
        match ctx.init(&store, &leaf.to_owned(), &chain, |c| c.verify_cert()) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Certificate verification failed".into()),
            Err(e) => Err(Box::new(e)),
        }
    }
}

impl Verifier<Certificate> for Certificate {
    fn verify(&self, other: &Certificate) -> Result<()> {
        Crypto::verify_chain(vec![self.to_owned()], vec![], other.to_owned())
    }
}

fn verify_report_sig_ecdsa_p384_sha384(
    cert: &Certificate,
    signed_bytes: &[u8],
    signature: Signature,
) -> Result<()> {
    let msg_hash = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), signed_bytes)?;

    let mut r = signature.r;
    let mut s = signature.s;
    // reverse to bring into big-endian format
    r.reverse();
    s.reverse();

    let ecdsa_sig = EcdsaSig::from_private_components(
        openssl::bn::BigNum::from_slice(&r)?,
        openssl::bn::BigNum::from_slice(&s)?,
    )?;

    let pub_key = cert.public_key()?;
    let ec_key = pub_key.ec_key()?;
    match ecdsa_sig.verify(&msg_hash, &ec_key) {
        Ok(true) => Ok(()),
        Ok(false) => Err("ECDSA signature verification failed".into()),
        Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
    }
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
    use zerocopy::{IntoBytes, TryFromBytes};

    use super::*;

    const MILAN_ARK: &[u8] = include_bytes!("test_data/milan_ark.pem");
    const MILAN_ASK: &[u8] = include_bytes!("test_data/milan_ask.pem");
    const MILAN_VCEK: &[u8] = include_bytes!("test_data/milan_vcek.pem");
    const MILAN_REPORT: &[u8] = include_bytes!("test_data/milan_attestation_report.bin");

    fn cert(pem: &[u8]) -> Certificate {
        openssl::x509::X509::from_pem(pem).unwrap()
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
    fn unrooted_certificates_fail() {
        Crypto::verify_chain(vec![cert(MILAN_ASK)], vec![], cert(MILAN_VCEK))
            .expect_err("VCEK should not verify with only ASK as trust anchor");
    }

    #[test]
    fn self_signed_certificates() {
        Crypto::verify_chain(vec![cert(MILAN_ARK)], vec![], cert(MILAN_ARK)).unwrap();
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
    fn attestation_report_signature_verifies() {
        let vcek = cert(MILAN_VCEK);
        let report: AttestationReport = AttestationReport::try_read_from_bytes(MILAN_REPORT)
            .expect("Failed to parse attestation report")
            .clone();
        println!("Attestation Report:\n{:#?}", report);
        println!(
            "Certificate:\n{}",
            String::from_utf8_lossy(&vcek.to_text().unwrap())
        );
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
