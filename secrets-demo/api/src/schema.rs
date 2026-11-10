use crate::{auth::Caller, config::Config, secrets, AppState};
use async_graphql::{
    Context, EmptyMutation, Json, Object, Result, Schema, SimpleObject, Subscription,
};
use chrono::{DateTime, Utc};
use futures_util::Stream;
use serde_json::Value;
use std::{sync::Arc, time::Duration};

pub type ApiSchema = Schema<Query, EmptyMutation, Sub>;

pub fn build(state: Arc<AppState>) -> ApiSchema {
    Schema::build(Query, EmptyMutation, Sub)
        .data(state)
        .finish()
}

#[derive(SimpleObject)]
pub struct Runtime {
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
    pub node_name: Option<String>,
    pub service_account: Option<String>,
    pub hostname: Option<String>,
}

#[derive(SimpleObject)]
pub struct ConfigInfo {
    pub app_name: String,
    pub scenario: String,
    pub description: String,
    pub version: String,
    pub watch_interval_ms: i32,
    pub spiffe_enabled: bool,
    pub config_file: String,
    /// The raw configuration file as mounted from the ConfigMap.
    pub raw_file: Option<String>,
    /// The effective configuration after defaults/overrides.
    pub effective: Json<Value>,
    pub runtime: Runtime,
}

#[derive(SimpleObject)]
pub struct Identity {
    pub spiffe_enabled: bool,
    pub audience: Option<String>,
    pub allowed_ids: Vec<String>,
    /// Who the API believes is calling (from the validated JWT-SVID).
    pub caller: Option<Json<Value>>,
    /// The API's own X.509-SVID.
    pub own_x509: Option<Json<Value>>,
    pub error: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct SecretUpdate {
    pub sequence: i32,
    pub secret: secrets::Secret,
    pub previous_value: Option<String>,
    pub observed_at: DateTime<Utc>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

pub struct Query;

#[Object]
impl Query {
    /// All secrets currently exposed to this pod (optionally filtered by delivery method).
    async fn secrets(
        &self,
        ctx: &Context<'_>,
        method: Option<String>,
    ) -> Result<Vec<secrets::Secret>> {
        let st = ctx.data::<Arc<AppState>>()?;
        Ok(secrets::collect(&st.config)
            .into_iter()
            .filter(|s| method.as_ref().is_none_or(|m| &s.method == m))
            .collect())
    }

    async fn secret(&self, ctx: &Context<'_>, name: String) -> Result<Option<secrets::Secret>> {
        let st = ctx.data::<Arc<AppState>>()?;
        Ok(secrets::find(&st.config, &name))
    }

    /// The configuration of the API (as set in its ConfigMap) plus pod runtime info.
    async fn config(&self, ctx: &Context<'_>) -> Result<ConfigInfo> {
        let st = ctx.data::<Arc<AppState>>()?;
        let c: &Config = &st.config;
        Ok(ConfigInfo {
            app_name: c.app_name.clone(),
            scenario: c.scenario.clone(),
            description: c.description.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            watch_interval_ms: c.watch_interval_ms as i32,
            spiffe_enabled: c.spiffe.enabled,
            config_file: st.config_path.clone(),
            raw_file: st.config_raw.clone(),
            effective: Json(serde_json::to_value(c)?),
            runtime: Runtime {
                pod_name: env("POD_NAME"),
                namespace: env("POD_NAMESPACE"),
                node_name: env("NODE_NAME"),
                service_account: env("POD_SERVICE_ACCOUNT"),
                hostname: env("HOSTNAME"),
            },
        })
    }

    /// SPIFFE details: who called, and who the API is.
    async fn identity(&self, ctx: &Context<'_>) -> Result<Identity> {
        let st = ctx.data::<Arc<AppState>>()?;
        let s = &st.config.spiffe;
        let caller = ctx
            .data_opt::<Caller>()
            .map(|c| Json(serde_json::to_value(&c.0).unwrap_or_default()));
        let (own_x509, error) = if s.enabled {
            match st.workload_client().await {
                Ok(cl) => match spiffe_util::x509_details(&cl).await {
                    Ok(d) => (Some(Json(serde_json::to_value(d)?)), None),
                    Err(e) => (None, Some(e.to_string())),
                },
                Err(e) => (None, Some(e.to_string())),
            }
        } else {
            (None, None)
        };
        Ok(Identity {
            spiffe_enabled: s.enabled,
            audience: s.enabled.then(|| s.audience.clone()),
            allowed_ids: s.allowed_ids.clone(),
            caller,
            own_x509,
            error,
        })
    }
}

pub struct Sub;

#[Subscription]
impl Sub {
    /// Emits the current value of a secret immediately, then again whenever it changes
    /// (e.g. when a sidecar rewrites the mounted file).
    async fn secret_value(
        &self,
        ctx: &Context<'_>,
        name: String,
    ) -> Result<impl Stream<Item = SecretUpdate>> {
        let st = ctx.data::<Arc<AppState>>()?.clone();
        let every = Duration::from_millis(st.config.watch_interval_ms.max(100));
        Ok(async_stream::stream! {
            let mut seq = 0;
            let mut last: Option<secrets::Secret> = None;
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let cfg = st.config.clone();
                let n = name.clone();
                let Ok(Some(cur)) = tokio::task::spawn_blocking(move || secrets::find(&cfg, &n)).await else {
                    continue;
                };
                // modification time alone is not a change; value/existence/error is.
                let changed = last.as_ref().is_none_or(|l| {
                    l.value != cur.value || l.exists != cur.exists || l.error != cur.error
                });
                if changed {
                    seq += 1;
                    yield SecretUpdate {
                        sequence: seq,
                        previous_value: last.as_ref().and_then(|l| l.value.clone()),
                        secret: cur.clone(),
                        observed_at: Utc::now(),
                    };
                    last = Some(cur);
                }
            }
        })
    }
}
