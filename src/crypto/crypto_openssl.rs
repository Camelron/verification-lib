use openssl::ecdsa;
use openssl::ecdsa::EcdsaSig;
use openssl::stack::Stack;
use openssl::x509;
use sev::firmware::guest::AttestationReport;

use crate::crypto::CryptoBackend;
use crate::crypto::Result;
use crate::crypto::Verifier;

pub struct Crypto;

type Certificate = openssl::x509::X509;

impl CryptoBackend for Crypto {
    type Certificate = Certificate;
}

fn verify_chain(trusted_certs: Vec<Certificate>, cert_chain: Vec<Certificate>) -> Result<()> {
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
    for cert in trusted_certs {
        store_builder.add_cert(cert)?;
    }
    let store = store_builder.build();
    let mut ctx = openssl::x509::X509StoreContext::new()?;
    let mut chain = Stack::new()?;
    for cert in cert_chain.iter().skip(1) {
        chain.push(cert.to_owned())?;
    }
    ctx.init(&store, &cert_chain[0], &chain, |c| c.verify_cert())?;
    Ok(())
}

impl Verifier<Certificate> for Certificate {
    fn verify(&self, other: &Certificate) -> Result<()> {
        verify_chain(vec![self.to_owned()], vec![other.to_owned()])
    }
}

impl Verifier<Vec<Certificate>> for Certificate {
    fn verify(&self, other: &Vec<Certificate>) -> Result<()> {
        verify_chain(vec![self.to_owned()], other.to_owned())
    }
}

impl Verifier<AttestationReport> for Certificate {
    fn verify(&self, report: &AttestationReport) -> Result<()> {
        // Get these from the report
        let r: [u8; 72] = todo!();
        let s: [u8; 72] = todo!();

        // need to reverse r and s as openssl bindings require big-endian
        let r_be = r.iter().copied().rev().collect::<Vec<u8>>();
        let s_be = s.iter().copied().rev().collect::<Vec<u8>>();

        let r = openssl::bn::BigNum::from_slice(&r_be)?;
        let s = openssl::bn::BigNum::from_slice(&s_be)?;
        let sig = ecdsa::EcdsaSig::from_private_components(r, s)?;

        let pub_key = self.public_key()?;
        let pub_key_ec = pub_key.ec_key()?;

        let report_bytes = todo!();
        let signed_data = report_bytes[..todo!()];
        let verified = sig.verify(&signed_data, &pub_key_ec)?;
    }
}
