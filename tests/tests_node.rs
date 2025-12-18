mod common;

use wasm_bindgen_test::wasm_bindgen_test;
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_node_experimental);

#[wasm_bindgen_test]
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
