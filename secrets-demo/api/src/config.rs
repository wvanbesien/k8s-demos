use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    File,
    Env,
}

/// One explicitly-configured secret.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SecretSpec {
    pub name: String,
    /// Free-text label describing *how* the secret got here
    /// (e.g. `k8s-secret-env`, `vault-agent-injector`, `csi-driver`).
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub kind: Kind,
    /// File path (kind=file) or environment variable name (kind=env).
    pub source: String,
}

/// Every regular file below `path` is exposed as a secret (kind=file).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DirSpec {
    pub path: String,
    #[serde(default)]
    pub method: String,
    /// Prepended to the file's relative path to build the secret name.
    #[serde(default)]
    pub name_prefix: String,
}

/// Every environment variable starting with `prefix` is exposed as a secret (kind=env).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EnvPrefixSpec {
    pub prefix: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub name_prefix: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct SpiffeConfig {
    pub enabled: bool,
    /// Audience a caller's JWT-SVID must be issued for.
    pub audience: String,
    /// If non-empty, only these SPIFFE IDs may call the API (authorisation).
    pub allowed_ids: Vec<String>,
    /// Workload API socket; falls back to SPIFFE_ENDPOINT_SOCKET.
    pub socket: String,
}

impl Default for SpiffeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audience: "secrets-demo-api".into(),
            allowed_ids: vec![],
            socket: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub app_name: String,
    /// Free-text name of the scenario being demonstrated; shown in the UI.
    pub scenario: String,
    pub description: String,
    pub listen_addr: String,
    pub watch_interval_ms: u64,
    pub secrets: Vec<SecretSpec>,
    pub secret_dirs: Vec<DirSpec>,
    pub env_prefixes: Vec<EnvPrefixSpec>,
    pub spiffe: SpiffeConfig,
    /// Arbitrary extra key/values to display (e.g. vault role, conjur host id).
    pub labels: BTreeMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app_name: "secrets-demo-api".into(),
            scenario: "default".into(),
            description: String::new(),
            listen_addr: "0.0.0.0:8080".into(),
            watch_interval_ms: 1000,
            secrets: vec![],
            secret_dirs: vec![],
            env_prefixes: vec![],
            spiffe: SpiffeConfig::default(),
            labels: BTreeMap::new(),
        }
    }
}

pub struct Loaded {
    pub config: Config,
    pub path: String,
    pub raw: Option<String>,
}

fn env_bool(k: &str) -> Option<bool> {
    std::env::var(k)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

pub fn load() -> anyhow::Result<Loaded> {
    let path =
        std::env::var("CONFIG_FILE").unwrap_or_else(|_| "/etc/secrets-demo/config.yaml".into());
    let raw = std::fs::read_to_string(&path).ok();
    let mut config: Config = match &raw {
        Some(r) => serde_yaml_ng::from_str(r)?,
        None => Config::default(),
    };
    // A few env overrides so `docker run -e ...` works without a config file.
    if let Ok(v) = std::env::var("LISTEN_ADDR") {
        config.listen_addr = v;
    }
    if let Some(v) = env_bool("SPIFFE_ENABLED") {
        config.spiffe.enabled = v;
    }
    Ok(Loaded { config, path, raw })
}
