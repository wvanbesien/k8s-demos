use crate::config::{Config, Kind};
use async_graphql::{Enum, SimpleObject};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum SecretKind {
    Env,
    File,
}

#[derive(SimpleObject, Clone, Debug, PartialEq)]
pub struct Secret {
    pub name: String,
    /// How the secret was delivered (label from the config).
    pub method: String,
    pub kind: SecretKind,
    /// Env var name or file path.
    pub location: String,
    pub exists: bool,
    pub value: Option<String>,
    pub error: Option<String>,
    pub size_bytes: Option<i32>,
    pub sha256: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
}

fn clean(s: String) -> String {
    s.trim_end_matches(['\n', '\r']).to_string()
}

fn finish(mut s: Secret, value: String, modified: Option<DateTime<Utc>>) -> Secret {
    s.exists = true;
    s.size_bytes = Some(value.len() as i32);
    s.sha256 = Some(hex::encode(Sha256::digest(value.as_bytes())));
    s.value = Some(value);
    s.last_modified = modified;
    s
}

fn blank(name: &str, method: &str, kind: SecretKind, location: &str) -> Secret {
    Secret {
        name: name.into(),
        method: method.into(),
        kind,
        location: location.into(),
        exists: false,
        value: None,
        error: None,
        size_bytes: None,
        sha256: None,
        last_modified: None,
    }
}

pub fn read_env(name: &str, method: &str, var: &str) -> Secret {
    let s = blank(name, method, SecretKind::Env, var);
    match std::env::var(var) {
        Ok(v) => finish(s, clean(v), None),
        Err(_) => Secret {
            error: Some(format!("environment variable {var} is not set")),
            ..s
        },
    }
}

pub fn read_file(name: &str, method: &str, path: &str) -> Secret {
    let s = blank(name, method, SecretKind::File, path);
    match std::fs::read(path) {
        Ok(bytes) => {
            let modified = std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .map(DateTime::<Utc>::from);
            finish(
                s,
                clean(String::from_utf8_lossy(&bytes).into_owned()),
                modified,
            )
        }
        Err(e) => Secret {
            error: Some(format!("{path}: {e}")),
            ..s
        },
    }
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        // Skip Kubernetes' atomic-writer internals (..data, ..2024_...) and dotfiles.
        if name.starts_with('.') {
            continue;
        }
        let p = e.path();
        // metadata() follows symlinks, which is how Secret/ConfigMap volumes are laid out.
        match std::fs::metadata(&p) {
            Ok(m) if m.is_dir() && depth < 4 => walk(&p, depth + 1, out),
            Ok(m) if m.is_file() => out.push(p),
            _ => {}
        }
    }
}

/// Resolve every secret the config exposes, reading current values.
pub fn collect(cfg: &Config) -> Vec<Secret> {
    let mut out = vec![];
    for s in &cfg.secrets {
        out.push(match s.kind {
            Kind::Env => read_env(&s.name, &s.method, &s.source),
            Kind::File => read_file(&s.name, &s.method, &s.source),
        });
    }
    for d in &cfg.secret_dirs {
        let root = Path::new(&d.path);
        let mut files = vec![];
        walk(root, 0, &mut files);
        if files.is_empty() && !root.exists() {
            let mut s = blank(
                &format!("{}(missing dir)", d.name_prefix),
                &d.method,
                SecretKind::File,
                &d.path,
            );
            s.error = Some(format!("directory {} does not exist", d.path));
            out.push(s);
        }
        for f in files {
            let rel = f
                .strip_prefix(root)
                .unwrap_or(&f)
                .to_string_lossy()
                .to_string();
            out.push(read_file(
                &format!("{}{}", d.name_prefix, rel),
                &d.method,
                &f.to_string_lossy(),
            ));
        }
    }
    for p in &cfg.env_prefixes {
        let mut vars: Vec<_> = std::env::vars()
            .filter(|(k, _)| k.starts_with(&p.prefix))
            .collect();
        vars.sort();
        for (k, _) in vars {
            let name = format!("{}{}", p.name_prefix, &k[p.prefix.len()..]);
            out.push(read_env(&name, &p.method, &k));
        }
    }
    out
}

pub fn find(cfg: &Config, name: &str) -> Option<Secret> {
    collect(cfg).into_iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DirSpec};

    #[test]
    fn dir_scan_follows_k8s_symlink_layout_and_skips_internals() {
        let root = std::env::temp_dir().join(format!("sd-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("..2026_01")).unwrap();
        std::fs::write(root.join("..2026_01/pw"), "v1\n").unwrap();
        std::os::unix::fs::symlink("..2026_01", root.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/pw", root.join("pw")).unwrap();
        let cfg = Config {
            secret_dirs: vec![DirSpec {
                path: root.to_string_lossy().into(),
                method: "m".into(),
                name_prefix: "p/".into(),
            }],
            ..Default::default()
        };
        let got = collect(&cfg);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].name, "p/pw");
        assert_eq!(got[0].value.as_deref(), Some("v1"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_sources_report_errors_not_panics() {
        assert!(!read_file("x", "m", "/nonexistent/file").exists);
        assert!(read_env("x", "m", "SD_SURELY_UNSET_VAR").error.is_some());
    }
}
