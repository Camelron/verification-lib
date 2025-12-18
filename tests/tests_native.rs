#![cfg(not(target_arch = "wasm32"))]

mod common;

#[tokio::test]
async fn test_verify_attestation() {
    let result = common::verify_milan_attestation()
        .await
        .expect("Verification call failed");

    assert!(
        result.is_valid,
        "Verification should pass: {:?}",
        result.errors
    );
}
