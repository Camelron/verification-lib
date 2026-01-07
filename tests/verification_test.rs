use verification_lib::{AttestationReport, SevVerifier};
use verification_lib::{snp_report, verify_with_chain};
use x509_cert::der::DecodePem;
use zerocopy::TryFromBytes;

const MILAN_ATTESTATION: &str = "03000000020000001f000300000000000100000000000000000000000000000002000000000000000000000000000000000000000100000004000000000018db25000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca14f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d100ad79ceb0b648b0e6a90d8aa9f6ea24c33a968b6632085353145e8b19a4741a2dab9ba342e13be4fc0d225e889cc1a580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005e01036273418d910bdca3f5cb9c7d849e88e2141483eb6cc9afd794ffbbbcbcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff04000000000018db1901010000000000000000000000000000000000000000004ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a11df2ca282add516bef45a890a8c9f9732bdca68f9f3f16c42e846030a800295dbeb19ba504000000000018db1d3701001d37010004000000000018db000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4c97ce68cfa7fe769a569fc55cee5ad38b238a4e1db928436a006b76e9a5885851d13c88892e5ffd93f3e1cf853f3b70000000000000000000000000000000000000000000000001e739e881fffadfeab34e3fb205ff0a5d8992496d0fb390a18baa725de048253e664e519b8f38309061b4af2a3e69f530000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

const MILAN_ASK_PEM: &str = include_str!("../src/crypto/test_data/milan_ask.pem");
const MILAN_VCEK_PEM: &str = include_str!("../src/crypto/test_data/milan_vcek.pem");
const MILAN_REPORT: &[u8] = include_bytes!("../src/crypto/test_data/milan_attestation_report.bin");

#[tokio::test]
async fn test_verify_attestation() {
    let hex_input = MILAN_ATTESTATION;

    // Parse hex to bytes
    let bytes = hex::decode(hex_input).expect("Failed to decode hex");

    // Parse the bytes as an AttestationReport
    let attestation_report: AttestationReport =
        AttestationReport::from_bytes(&bytes).expect("Failed to parse attestation report");

    // Create verifier and run verification
    let mut verifier = SevVerifier::new()
        .await
        .expect("Failed to initialize verifier");

    let result = verifier
        .verify_attestation(&attestation_report)
        .await
        .expect("Verification call failed");

    assert!(
        result.is_valid,
        "Verification should pass: {:?}",
        result.errors
    );
}

#[test]
fn test_verify_with_chain_success() {
    let ask = x509_cert::Certificate::from_pem(MILAN_ASK_PEM).expect("Failed to parse ASK");
    let vcek = x509_cert::Certificate::from_pem(MILAN_VCEK_PEM).expect("Failed to parse VCEK");
    let report = snp_report::AttestationReport::try_read_from_bytes(MILAN_REPORT)
        .expect("Failed to parse attestation report")
        .clone();

    // Verify with ASK as the untrusted intermediate and VCEK as the leaf
    verify_with_chain(&report, vec![ask], vcek).expect("Verification should succeed");
}

#[test]
fn test_verify_with_chain_missing_intermediate() {
    let vcek = x509_cert::Certificate::from_pem(MILAN_VCEK_PEM).expect("Failed to parse VCEK");
    let report = snp_report::AttestationReport::try_read_from_bytes(MILAN_REPORT)
        .expect("Failed to parse attestation report")
        .clone();

    // Should fail without the ASK intermediate
    verify_with_chain(&report, vec![], vcek)
        .expect_err("Should fail without intermediate certificate");
}

#[test]
fn test_verify_with_chain_wrong_leaf() {
    let ask = x509_cert::Certificate::from_pem(MILAN_ASK_PEM).expect("Failed to parse ASK");
    let report = snp_report::AttestationReport::try_read_from_bytes(MILAN_REPORT)
        .expect("Failed to parse attestation report")
        .clone();

    // Using ASK as leaf (wrong cert) should fail signature verification
    verify_with_chain(&report, vec![], ask)
        .expect_err("Should fail with wrong leaf certificate");
}
