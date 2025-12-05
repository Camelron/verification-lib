use std::env;
use verification_lib::{AttestationReport, SevVerifier};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <hex_string>", args[0]);
        std::process::exit(1);
    }

    let hex_input = &args[1];

    // Validate hex string
    match hex::decode(hex_input) {
        Ok(bytes) => {
            // Parse the bytes as an AttestationReport
            let attestation_report: AttestationReport = AttestationReport::from_bytes(&bytes).unwrap_or_else(|e| {
                eprintln!("Failed to parse attestation report: {}", e);
                std::process::exit(1);
            });

            // Create verifier and run verification
            let mut verifier = match SevVerifier::new().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to initialize verifier: {}", e);
                    std::process::exit(1);
                }
            };

            let res = verifier.verify_attestation(&attestation_report).await;
            println!("Verification result: {:?}", res);
        }
        Err(e) => {
            eprintln!("Invalid hex string: {}", e);
            std::process::exit(1);
        }
    }
}
