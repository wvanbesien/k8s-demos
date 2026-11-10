//! Small helpers shared by the API and the web front end for talking to the
//! SPIFFE Workload API and turning SVIDs into something a human can read.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use serde_json::Value;
pub use spiffe::WorkloadApiClient;
use x509_parser::prelude::*;

/// Connect to the Workload API. `socket` (e.g. `unix:///spiffe-workload-api/agent.sock`)
/// wins; otherwise `SPIFFE_ENDPOINT_SOCKET` is used.
pub async fn connect(socket: Option<&str>) -> Result<WorkloadApiClient> {
    match socket.filter(|s| !s.is_empty()) {
        Some(s) => WorkloadApiClient::connect_to(s).await,
        None => WorkloadApiClient::connect_env().await,
    }
    .map_err(|e| anyhow!("cannot connect to SPIFFE Workload API: {e}"))
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct X509Details {
    pub spiffe_id: String,
    pub trust_domain: String,
    pub serial: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub expires_in_secs: i64,
    pub san_uris: Vec<String>,
    pub signature_algorithm: String,
    pub chain_length: usize,
    pub certificate_pem: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JwtDetails {
    pub spiffe_id: String,
    pub audience: Vec<String>,
    pub issued_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub expires_in_secs: Option<i64>,
    pub header: Value,
    pub claims: Value,
    pub token: String,
}

fn pem(der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Fetch this workload's default X.509-SVID and describe its leaf certificate.
pub async fn x509_details(client: &WorkloadApiClient) -> Result<X509Details> {
    let svid = client
        .fetch_x509_svid()
        .await
        .map_err(|e| anyhow!("fetch X509-SVID: {e}"))?;
    let leaf = svid.leaf().as_bytes();
    let (_, cert) = X509Certificate::from_der(leaf).context("parse leaf certificate")?;
    let san_uris = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::URI(u) => Some(u.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let not_after = cert.validity().not_after.timestamp();
    let now = now_unix();
    Ok(X509Details {
        spiffe_id: svid.spiffe_id().to_string(),
        trust_domain: svid.spiffe_id().trust_domain().to_string(),
        serial: cert.raw_serial_as_string(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        expires_in_secs: not_after - now,
        san_uris,
        signature_algorithm: cert.signature_algorithm.algorithm.to_id_string(),
        chain_length: svid.cert_chain().len(),
        certificate_pem: pem(leaf),
    })
}

/// Fetch a JWT-SVID for `audience` from the Workload API and decode it.
pub async fn fetch_jwt(client: &WorkloadApiClient, audience: &str) -> Result<JwtDetails> {
    let token = client
        .fetch_jwt_token([audience], None)
        .await
        .map_err(|e| anyhow!("fetch JWT-SVID: {e}"))?;
    decode_jwt(&token)
}

/// Decode (without verifying!) a JWT for display purposes.
pub fn decode_jwt(token: &str) -> Result<JwtDetails> {
    let mut parts = token.split('.');
    let (h, c) = (parts.next(), parts.next());
    let (Some(h), Some(c)) = (h, c) else {
        return Err(anyhow!("not a JWT"));
    };
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h)?)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(c)?)?;
    let now = now_unix();
    let exp = claims["exp"].as_i64();
    let audience = match &claims["aud"] {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => vec![],
    };
    Ok(JwtDetails {
        spiffe_id: claims["sub"].as_str().unwrap_or_default().to_string(),
        audience,
        issued_at: claims["iat"].as_i64(),
        expires_at: exp,
        expires_in_secs: exp.map(|e| e - now),
        header,
        claims,
        token: token.to_string(),
    })
}

/// Validate a JWT-SVID presented by a caller. Signature, expiry and audience are
/// checked by the Workload API provider; we only parse the result.
pub async fn validate_jwt(
    client: &WorkloadApiClient,
    audience: &str,
    token: &str,
) -> Result<JwtDetails> {
    client
        .validate_jwt_token(audience, token)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    decode_jwt(token)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_jwt_for_display() {
        let enc = |v: &str| URL_SAFE_NO_PAD.encode(v);
        let tok = format!(
            "{}.{}.sig",
            enc(r#"{"alg":"ES256","kid":"k1"}"#),
            enc(r#"{"sub":"spiffe://example.org/web","aud":["api"],"exp":4102444800,"iat":1}"#)
        );
        let d = decode_jwt(&tok).unwrap();
        assert_eq!(d.spiffe_id, "spiffe://example.org/web");
        assert_eq!(d.audience, vec!["api"]);
        assert_eq!(d.header["kid"], "k1");
        assert!(d.expires_in_secs.unwrap() > 0);
        assert!(decode_jwt("garbage").is_err());
    }
}
