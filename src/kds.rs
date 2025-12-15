use crate::{certificate_chain::CertificateFetcher, AttestationReport};
use hex;
use js_sys::{Promise, Uint8Array};
use log::info;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use x509_cert::{der::Decode, Certificate};

/// Cache entry for certificate chain
type ChainCache = Option<(Certificate, Certificate)>;

/// KDS (Key Distribution Service) certificate fetcher
/// Fetches certificates from AMD's public KDS service
#[cfg(target_arch = "wasm32")]
pub(crate) struct KdsFetcher {
    chain_cache: ChainCache,
    vcek_cache: std::collections::HashMap<String, Certificate>,
    use_cache: bool,
}

#[cfg(target_arch = "wasm32")]
impl KdsFetcher {
    pub(crate) fn new() -> Self {
        Self {
            chain_cache: None,
            vcek_cache: std::collections::HashMap::new(),
            use_cache: false,
        }
    }

    pub(crate) fn with_cache() -> Self {
        Self {
            chain_cache: None,
            vcek_cache: std::collections::HashMap::new(),
            use_cache: true,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl CertificateFetcher for KdsFetcher {
    async fn fetch_amd_chain(
        &mut self,
    ) -> Result<(Certificate, Certificate), Box<dyn std::error::Error>> {
        // Check cache for ARK/ASK
        if self.use_cache {
            if let Some((ark, ask)) = &self.chain_cache {
                info!("Using cached AMD certificate chain (ARK/ASK)");
                return Ok((ark.clone(), ask.clone()));
            }
        }

        // Fetch PEM chain from KDS - use Milan as default processor model
        // TODO: rework to support other models (not just Milan)
        let cert_chain_url = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain";
        let pem_bytes = fetch_url_bytes(cert_chain_url).await?;
        let pems = pem::parse_many(&pem_bytes)
            .map_err(|e| format!("Failed to parse PEM certificates: {}", e))?;
        if pems.len() < 2 {
            return Err("Certificate chain must contain at least 2 certificates".into());
        }
        let ark_der = pems[1].contents().to_vec();
        let ask_der = pems[0].contents().to_vec();

        let ark = Certificate::from_der(&ark_der)
            .map_err(|e| format!("Failed to parse ARK certificate: {}", e))?;
        let ask = Certificate::from_der(&ask_der)
            .map_err(|e| format!("Failed to parse ASK certificate: {}", e))?;

        // Store in cache if requested
        if self.use_cache {
            self.chain_cache = Some((ark.clone(), ask.clone()));
            info!("Cached AMD certificate chain (ARK/ASK)");
        }

        Ok((ark, ask))
    }

    async fn fetch_amd_vcek(
        &mut self,
        processor_model: &str,
        attestation_report: &AttestationReport,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        // Build a cache key using processor model and first 8 bytes of the chip id
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );

        if self.use_cache {
            if let Some(cached) = self.vcek_cache.get(&cache_key) {
                // Return cached VCEK certificate immediately
                info!("Using cached VCEK certificate (cache_key={})", cache_key);
                return Ok(cached.clone());
            }
        }

        // Build VCEK URL based on processor model and reported TCB
        let chip_id_hex = if attestation_report.chip_id.iter().all(|&b| b == 0) {
            return Err(
                "Hardware ID is 0s on attestation report. Confirm that MASK_CHIP_ID is set to 0."
                    .into(),
            );
        } else {
            match processor_model {
                "Turin" => {
                    // Turin uses only first 8 bytes of chip_id
                    hex::encode(&attestation_report.chip_id[0..8]).to_uppercase()
                }
                _ => {
                    // Milan and Genoa use full chip_id
                    hex::encode(&attestation_report.chip_id.as_ref()).to_uppercase()
                }
            }
        };

        let vcek_url = match processor_model {
            "Turin" => {
                // Turin requires FMC parameter
                let fmc = attestation_report
                    .reported_tcb
                    .fmc
                    .ok_or("A Turin processor must have a fmc value")?;
                format!(
                    "https://kdsintf.amd.com/vcek/v1/{}/{}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    processor_model,
                    chip_id_hex,
                    fmc,
                    attestation_report.reported_tcb.bootloader,
                    attestation_report.reported_tcb.tee,
                    attestation_report.reported_tcb.snp,
                    attestation_report.reported_tcb.microcode
                )
            }
            _ => {
                // Milan and Genoa don't use FMC parameter
                format!(
                    "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    processor_model,
                    chip_id_hex,
                    attestation_report.reported_tcb.bootloader,
                    attestation_report.reported_tcb.tee,
                    attestation_report.reported_tcb.snp,
                    attestation_report.reported_tcb.microcode
                )
            }
        };

        let vcek_bytes = fetch_url_bytes(&vcek_url).await?;

        let vcek = Certificate::from_der(&vcek_bytes)
            .map_err(|e| format!("Failed to parse VCEK certificate: {}", e))?;

        // Store into cache if requested
        if self.use_cache {
            self.vcek_cache.insert(cache_key.clone(), vcek.clone());
            info!("Cached VCEK certificate (cache_key={})", cache_key);
        }

        Ok(vcek)
    }
}

/// wasm fetch helper
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = __patty_fetch_bytes)]
    fn fetch_bytes_promise(url: &str) -> Promise;
}

async fn fetch_url_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let promise: Promise = fetch_bytes_promise(url);
    let js_val = JsFuture::from(promise)
        .await
        .map_err(|e| format!("JS fetch error: {:?}", e))?;
    let u8arr = Uint8Array::new(&js_val);
    let mut vec = vec![0u8; u8arr.length() as usize];
    u8arr.copy_to(&mut vec[..]);
    Ok(vec)
}
