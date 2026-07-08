use base64::Engine;
use ed25519_dalek::Verifier as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

pub const TIME_SOURCES: &[&str] = &["https://www.baidu.com", "https://www.aliyun.com"];
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const IAT_SKEW_TOLERANCE: u64 = 86400;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid license key format")]
    InvalidFormat,
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("license key expired (exp={exp}, now={now})")]
    Expired { exp: u64, now: u64 },
    #[error("license key not yet valid (iat={iat}, now={now})")]
    NotYetValid { iat: u64, now: u64 },
    #[error("time fetch failed: {0}")]
    TimeFetch(String),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Deserialize, Serialize)]
struct Payload {
    exp: u64,
    iat: u64,
}

#[derive(Debug)]
pub struct LicenseInfo {
    pub exp: u64,
    pub iat: u64,
}

pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    rand::fill(&mut secret[..]);
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes(), verifying_key.to_bytes())
}

pub fn create_license(sk: &[u8; 32], exp: u64) -> String {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload_bytes = serde_json::to_vec(&Payload { exp, iat }).unwrap();
    let sig = SigningKey::from_bytes(sk).sign(&payload_bytes);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload_bytes);
    let sig_hex = hex::encode(sig.to_bytes());
    format!("v1.{}.{}", encoded, sig_hex)
}

pub async fn verify_license(pk: &[u8; 32], license: &str, time_sources: &[&str]) -> Result<LicenseInfo, Error> {
    let public_key = VerifyingKey::from_bytes(pk).map_err(|_| Error::InvalidFormat)?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(
        webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(),
    );
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(REQUEST_TIMEOUT)
        .build()?;

    let info = parse_license_key(&public_key, license)?;
    let now = fetch_trusted_time(&client, time_sources).await?;

    if now > info.exp {
        return Err(Error::Expired { exp: info.exp, now });
    }
    if info.iat.saturating_sub(IAT_SKEW_TOLERANCE) > now {
        return Err(Error::NotYetValid { iat: info.iat, now });
    }

    Ok(info)
}

fn parse_license_key(public_key: &VerifyingKey, key: &str) -> Result<LicenseInfo, Error> {
    let parts: Vec<&str> = key.splitn(3, '.').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return Err(Error::InvalidFormat);
    }

    let payload_bytes = base64::engine::general_purpose::STANDARD.decode(parts[1])?;
    let sig_bytes = hex::decode(parts[2])?;

    let signature = Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidFormat)?;
    public_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| Error::InvalidSignature)?;

    let payload: Payload = serde_json::from_slice(&payload_bytes)?;
    Ok(LicenseInfo {
        exp: payload.exp,
        iat: payload.iat,
    })
}

async fn fetch_date_header(client: &reqwest::Client, url: &str) -> Result<u64, Error> {
    let cache_buster = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let url = format!("{}?t={}", url, cache_buster);

    let response = client
        .get(&url)
        .header("Cache-Control", "no-cache")
        .send()
        .await?;

    let date_str = response
        .headers()
        .get("date")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::TimeFetch("missing Date header".into()))?;

    let dt = OffsetDateTime::parse(date_str, &Rfc2822)
        .map_err(|e| Error::TimeFetch(format!("invalid Date header: {e}")))?;

    Ok(dt.unix_timestamp() as u64)
}

async fn fetch_trusted_time(client: &reqwest::Client, time_sources: &[&str]) -> Result<u64, Error> {
    let mut last_err = None;
    for url in time_sources {
        match fetch_date_header(client, url).await {
            Ok(ts) => return Ok(ts),
            Err(e) => last_err = Some(e),
        }
    }
    Err(Error::TimeFetch(format!(
        "all time sources failed: {}",
        last_err.as_ref().map(|e| e.to_string()).unwrap_or_default()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut secret = [0u8; 32];
        rand::fill(&mut secret[..]);
        let sk = SigningKey::from_bytes(&secret);
        (sk.to_bytes(), sk.verifying_key().to_bytes())
    }

    #[test]
    fn generate_keypair_returns_nonzero() {
        let (sk, pk) = generate_keypair();
        assert_ne!(sk, [0u8; 32]);
        assert_ne!(pk, [0u8; 32]);
    }

    #[test]
    fn create_license_format() {
        let (sk, _) = generate_keypair();
        let license = create_license(&sk, 9999999999);
        assert!(license.starts_with("v1."));
        assert_eq!(license.splitn(3, '.').count(), 3);
    }

    #[test]
    fn create_license_iat_is_recent() {
        let (sk, _) = generate_keypair();
        let license = create_license(&sk, 9999999999);
        let parts: Vec<&str> = license.splitn(3, '.').collect();
        let payload: Payload =
            serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap()).unwrap();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(payload.iat <= now);
        assert!(payload.iat > now - 10);
    }

    #[test]
    fn signature_roundtrip() {
        let (sk, pk) = generate_keypair();
        let pub_key = VerifyingKey::from_bytes(&pk).unwrap();
        let license = create_license(&sk, 9999999999);

        let info = parse_license_key(&pub_key, &license).unwrap();
        assert_eq!(info.exp, 9999999999);
    }

    #[test]
    fn wrong_key_rejected() {
        let (sk, _) = keypair();
        let (_, wrong_pk) = keypair();
        let wrong_pub = VerifyingKey::from_bytes(&wrong_pk).unwrap();
        let license = create_license(&sk, 9999999999);

        assert!(parse_license_key(&wrong_pub, &license).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, pk) = generate_keypair();
        let pub_key = VerifyingKey::from_bytes(&pk).unwrap();
        let license = create_license(&sk, 9999999999);

        let parts: Vec<&str> = license.splitn(3, '.').collect();
        let sig = hex::decode(parts[2]).unwrap();
        let mut tampered = sig;
        tampered[0] ^= 0x01;
        let bad = format!("v1.{}.{}", parts[1], hex::encode(tampered));

        assert!(parse_license_key(&pub_key, &bad).is_err());
    }

    #[test]
    fn tampered_payload_rejected() {
        let (sk, pk) = generate_keypair();
        let pub_key = VerifyingKey::from_bytes(&pk).unwrap();
        let license = create_license(&sk, 9999999999);

        let parts: Vec<&str> = license.splitn(3, '.').collect();
        let payload = base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap();
        let mut tampered = payload;
        tampered[0] ^= 0x01;
        let bad = format!(
            "v1.{}.{}",
            base64::engine::general_purpose::STANDARD.encode(tampered),
            parts[2]
        );

        assert!(parse_license_key(&pub_key, &bad).is_err());
    }

    #[test]
    fn invalid_format_rejected() {
        let (_, pk) = generate_keypair();
        let pub_key = VerifyingKey::from_bytes(&pk).unwrap();

        assert!(matches!(
            parse_license_key(&pub_key, "v2.payload.sig"),
            Err(Error::InvalidFormat)
        ));
        assert!(matches!(
            parse_license_key(&pub_key, "v1.only_two_parts"),
            Err(Error::InvalidFormat)
        ));
        assert!(matches!(
            parse_license_key(&pub_key, "not even close"),
            Err(Error::InvalidFormat)
        ));
    }

    #[test]
    fn bad_base64_rejected() {
        let (_, pk) = generate_keypair();
        let pub_key = VerifyingKey::from_bytes(&pk).unwrap();

        assert!(matches!(
            parse_license_key(&pub_key, "v1.!@#$.abcdef1234"),
            Err(Error::Base64(_))
        ));
    }

    #[test]
    fn bad_hex_rejected() {
        let (_, pk) = generate_keypair();
        let pub_key = VerifyingKey::from_bytes(&pk).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .encode(br#"{"exp":1,"iat":1}"#);

        assert!(matches!(
            parse_license_key(&pub_key, &format!("v1.{}.xyz", payload)),
            Err(Error::Hex(_))
        ));
    }

    #[test]
    fn short_signature_rejected() {
        let (_, pk) = generate_keypair();
        let pub_key = VerifyingKey::from_bytes(&pk).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .encode(br#"{"exp":1,"iat":1}"#);

        assert!(matches!(
            parse_license_key(&pub_key, &format!("v1.{}.aabbccdd", payload)),
            Err(Error::InvalidFormat)
        ));
    }

    #[test]
    fn error_display() {
        assert_eq!(
            Error::InvalidFormat.to_string(),
            "invalid license key format"
        );
        assert_eq!(
            Error::Expired { exp: 100, now: 200 }.to_string(),
            "license key expired (exp=100, now=200)"
        );
    }
}
