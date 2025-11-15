# verification-lib

A WASM-compatible Rust library for AMD SEV-SNP attestation verification.

## Overview

This library provides cryptographic verification of AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) attestation reports. It's designed to run in WebAssembly environments and uses pure-Rust cryptography implementations.

## Features

- **AMD SEV-SNP Attestation Verification**: Validates attestation reports from AMD EPYC processors
- **Certificate Chain Verification**: Automatically fetches and verifies AMD certificates (ARK → ASK → VCEK) from the AMD Key Distribution Server (KDS)
- **WASM-Compatible**: Built for `wasm32-unknown-unknown` target with no native dependencies
- **Caching Support**: Optional caching of certificates to reduce network requests

## Current Limitations

⚠️ **This library currently only supports AMD EPYC Milan (7xx3) processors.** The certificate chain is fetched directly from the KDS Milan endpoint. Support for other processor models (Genoa, Turin, etc.) requires fetching their respective certificate chains, which is not yet implemented.

## Usage

```rust
use verification_lib::verify_attestation_report;

// Parse and verify an attestation report
let result = verify_attestation_report(&attestation_json).await?;

if result.is_valid {
    println!("Attestation verified successfully!");
} else {
    println!("Verification failed: {:?}", result.errors);
}
```

## Building

Build for WebAssembly:

```bash
cargo build --target wasm32-unknown-unknown --release
```

## Verification Process

The library performs the following verification steps:

1. **Processor Identification**: Determines the processor model from the attestation report
2. **Certificate Fetching**: Retrieves ARK (AMD Root Key), ASK (AMD SEV Key), and VCEK (Versioned Chip Endorsement Key) from KDS
3. **Certificate Chain Validation**: Verifies ARK is self-signed, ASK is signed by ARK, and VCEK is signed by ASK
4. **Signature Verification**: Validates the attestation report signature using the VCEK public key
5. **TCB Verification**: Confirms Trusted Computing Base (TCB) values in the report match the VCEK certificate extensions

## Dependencies

- **x509-cert**: X.509 certificate parsing
- **p384**: ECDSA P-384 cryptography (used by AMD SEV-SNP)
- **sev**: AMD SEV types and utilities
- **wasm-bindgen**: WebAssembly bindings

## Contributing

Contributions welcome! Priority areas include:
- Support for Genoa, Turin, and other AMD processor models
- Additional attestation verification types (e.g., TDX)
- Testing collateral
