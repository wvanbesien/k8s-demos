use anyhow::Result;
use axum::{
    extract::{Query, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
struct SpiffeConfig {
    enabled: bool,
    /// Audience requested for the JWT-SVID; must match the API's `spiffe.audience`.
    audience: String,
    socket: String,
}
impl Default for SpiffeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audience: "secrets-demo-api".into(),
            socket: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
struct Config {
    app_name: String,
    scenario: String,
    description: String,
    listen_addr: String,
    api_url: String,
    /// How often the UI refreshes the secret list (ms). 0 disables auto refresh.
    refresh_interval_ms: u64,
    spiffe: SpiffeConfig,
    labels: BTreeMap<String, String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            app_name: "secrets-demo-web".into(),
            scenario: "default".into(),
            description: String::new(),
            listen_addr: "0.0.0.0:8080".into(),
            api_url: "http://secrets-demo-api:8080".into(),
            refresh_interval_ms: 5000,
            spiffe: SpiffeConfig::default(),
            labels: BTreeMap::new(),
        }
    }
}

struct State_ {
    cfg: Config,
    cfg_path: String,
    cfg_raw: Option<String>,
    http: reqwest::Client,
    workload: Mutex<Option<spiffe_util::WorkloadApiClient>>,
}
type S = Arc<State_>;

impl State_ {
    async fn client(&self) -> Result<spiffe_util::WorkloadApiClient> {
        let mut g = self.workload.lock().await;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let c = spiffe_util::connect(Some(&self.cfg.spiffe.socket)).await?;
        *g = Some(c.clone());
        Ok(c)
    }
    /// A JWT-SVID for the API if SPIFFE is enabled for the web, else None.
    async fn token(&self, audience: &str) -> Result<Option<String>> {
        if !self.cfg.spiffe.enabled {
            return Ok(None);
        }
        let c = self.client().await?;
        match spiffe_util::fetch_jwt(&c, audience).await {
            Ok(j) => Ok(Some(j.token)),
            Err(e) => {
                *self.workload.lock().await = None;
                Err(e)
            }
        }
    }
}

fn pod_env() -> Value {
    let g = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    json!({
        "podName": g("POD_NAME"), "namespace": g("POD_NAMESPACE"), "nodeName": g("NODE_NAME"),
        "serviceAccount": g("POD_SERVICE_ACCOUNT"), "hostname": g("HOSTNAME"),
        "spiffeEndpointSocket": g("SPIFFE_ENDPOINT_SOCKET"),
    })
}

async fn web_config(State(s): State<S>) -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "effective": s.cfg,
        "configFile": s.cfg_path,
        "rawFile": s.cfg_raw,
        "runtime": pod_env(),
    }))
}

/// POST a GraphQL request to the API, attaching `token` if given.
async fn post_api(s: &State_, token: Option<&str>, body: &Value) -> Value {
    let mut rb = s
        .http
        .post(format!("{}/graphql", s.cfg.api_url.trim_end_matches('/')))
        .timeout(Duration::from_secs(10))
        .json(body);
    if let Some(t) = token {
        rb = rb.bearer_auth(t);
    }
    match rb.send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            let parsed = serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text));
            json!({ "status": status, "ok": (200..300).contains(&status), "body": parsed })
        }
        Err(e) => {
            json!({ "status": 0, "ok": false, "body": { "error": format!("cannot reach API at {}: {e}", s.cfg.api_url) } })
        }
    }
}

#[derive(Deserialize)]
struct GqlReq {
    query: String,
    #[serde(default)]
    variables: Value,
}

/// Generic pass-through used by the UI. The browser never sees SPIFFE credentials; the
/// web back end attaches its own JWT-SVID when SPIFFE is enabled.
async fn graphql(State(s): State<S>, Json(r): Json<GqlReq>) -> Json<Value> {
    let token = match s.token(&s.cfg.spiffe.audience).await {
        Ok(t) => t,
        Err(e) => {
            return Json(json!({ "status": 0, "ok": false, "sentCredentials": false,
                "body": { "error": format!("web could not obtain a JWT-SVID: {e}") } }))
        }
    };
    let mut out = post_api(
        &s,
        token.as_deref(),
        &json!({ "query": r.query, "variables": r.variables }),
    )
    .await;
    out["sentCredentials"] = json!(token.is_some());
    Json(out)
}

async fn spiffe_info(State(s): State<S>) -> Json<Value> {
    let cfg = &s.cfg.spiffe;
    if !cfg.enabled {
        return Json(json!({ "enabled": false }));
    }
    let mut out = json!({ "enabled": true, "audience": cfg.audience });
    match s.client().await {
        Ok(c) => {
            match spiffe_util::x509_details(&c).await {
                Ok(d) => out["x509"] = serde_json::to_value(d).unwrap(),
                Err(e) => out["x509Error"] = json!(e.to_string()),
            }
            match spiffe_util::fetch_jwt(&c, &cfg.audience).await {
                Ok(d) => out["jwt"] = serde_json::to_value(d).unwrap(),
                Err(e) => out["jwtError"] = json!(e.to_string()),
            }
        }
        Err(e) => out["error"] = json!(e.to_string()),
    }
    Json(out)
}

/// Calls the API with a series of credentials to show what is (not) accepted.
async fn probe(State(s): State<S>) -> Json<Value> {
    let q = json!({ "query": "{ identity { spiffeEnabled caller } }" });
    let mut results = vec![];
    let mut add = |label: &str, desc: &str, sent: &str, r: Value| {
        results.push(json!({ "label": label, "description": desc, "sent": sent,
            "status": r["status"], "ok": r["ok"], "body": r["body"] }));
    };
    add(
        "No credentials",
        "A plain request, as any other pod (or curl on the NodePort) would make.",
        "nothing",
        post_api(&s, None, &q).await,
    );
    add(
        "Garbage token",
        "A bearer token that is not a valid JWT-SVID.",
        "Authorization: Bearer not-a-real-token",
        post_api(&s, Some("not-a-real-token"), &q).await,
    );
    if s.cfg.spiffe.enabled {
        match s.client().await {
            Ok(c) => {
                match spiffe_util::fetch_jwt(&c, "some-other-service").await {
                    Ok(j) => add("Valid SVID, wrong audience",
                        "A genuine JWT-SVID, but minted for a different audience, so it must not be accepted here.",
                        &format!("JWT-SVID {} aud=some-other-service", j.spiffe_id),
                        post_api(&s, Some(&j.token), &q).await),
                    Err(e) => add("Valid SVID, wrong audience", "", "-", json!({"status":0,"ok":false,"body":{"error":e.to_string()}})),
                }
                match spiffe_util::fetch_jwt(&c, &s.cfg.spiffe.audience).await {
                    Ok(j) => add("Valid JWT-SVID (what this web app uses)",
                        "JWT-SVID for the configured audience, issued to this workload via the Workload API.",
                        &format!("JWT-SVID {} aud={}", j.spiffe_id, s.cfg.spiffe.audience),
                        post_api(&s, Some(&j.token), &q).await),
                    Err(e) => add("Valid JWT-SVID", "", "-", json!({"status":0,"ok":false,"body":{"error":e.to_string()}})),
                }
            }
            Err(e) => add(
                "Valid JWT-SVID",
                "",
                "-",
                json!({"status":0,"ok":false,"body":{"error":e.to_string()}}),
            ),
        }
    }
    Json(json!({ "webSpiffeEnabled": s.cfg.spiffe.enabled, "results": results }))
}

#[derive(Deserialize)]
struct SubQ {
    name: String,
}

fn ev(name: &str, data: Value) -> Result<Event, Infallible> {
    Ok(Event::default().event(name).data(data.to_string()))
}

/// Bridges the API's GraphQL subscription (graphql-transport-ws) to Server-Sent Events.
async fn subscribe(State(s): State<S>, Query(q): Query<SubQ>) -> impl IntoResponse {
    let stream = async_stream::stream! {
        let token = match s.token(&s.cfg.spiffe.audience).await {
            Ok(t) => t,
            Err(e) => { yield ev("failure", json!({"error": format!("no JWT-SVID: {e}")})); return; }
        };
        let url = s.cfg.api_url.trim_end_matches('/').replacen("http", "ws", 1) + "/graphql/ws";
        let mut req = match url.as_str().into_client_request() {
            Ok(r) => r,
            Err(e) => { yield ev("failure", json!({"error": e.to_string()})); return; }
        };
        req.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static("graphql-transport-ws"));
        if let Some(t) = &token {
            req.headers_mut().insert("Authorization", HeaderValue::from_str(&format!("Bearer {t}")).unwrap());
        }
        let (mut ws, _) = match tokio_tungstenite::connect_async(req).await {
            Ok(x) => x,
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                let body = resp.body().as_ref().map(|b| String::from_utf8_lossy(b).to_string()).unwrap_or_default();
                yield ev("failure", json!({"status": resp.status().as_u16(), "error": "API rejected the WebSocket upgrade", "body": body}));
                return;
            }
            Err(e) => { yield ev("failure", json!({"error": format!("cannot connect to {url}: {e}")})); return; }
        };
        let _ = ws.send(Message::text(json!({"type":"connection_init"}).to_string())).await;
        let sub = json!({"id":"1","type":"subscribe","payload":{
            "query": "subscription($n:String!){ secretValue(name:$n){ sequence previousValue observedAt secret{ name method kind location value exists error sizeBytes sha256 lastModified } } }",
            "variables": {"n": q.name}}});
        let _ = ws.send(Message::text(sub.to_string())).await;
        yield ev("status", json!({"state": "subscribed", "sentCredentials": token.is_some()}));
        while let Some(m) = ws.next().await {
            let Ok(Message::Text(t)) = m else {
                if matches!(m, Ok(Message::Close(_)) | Err(_)) { break; }
                continue;
            };
            let Ok(v) = serde_json::from_str::<Value>(&t) else { continue };
            match v["type"].as_str() {
                Some("next") => yield ev("update", v["payload"].clone()),
                Some("error") => yield ev("failure", json!({"error": v["payload"]})),
                Some("ping") => { let _ = ws.send(Message::text(json!({"type":"pong"}).to_string())).await; }
                Some("complete") => break,
                _ => {}
            }
        }
        yield ev("status", json!({"state": "closed"}));
    };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let path =
        std::env::var("CONFIG_FILE").unwrap_or_else(|_| "/etc/secrets-demo/config.yaml".into());
    let raw = std::fs::read_to_string(&path).ok();
    let mut cfg: Config = match &raw {
        Some(r) => serde_yaml_ng::from_str(r)?,
        None => Config::default(),
    };
    if let Ok(v) = std::env::var("LISTEN_ADDR") {
        cfg.listen_addr = v;
    }
    if let Ok(v) = std::env::var("API_URL") {
        cfg.api_url = v;
    }
    if let Ok(v) = std::env::var("SPIFFE_ENABLED") {
        cfg.spiffe.enabled = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
    }
    tracing::info!(
        "config {path} (found={}): api={} spiffe={}",
        raw.is_some(),
        cfg.api_url,
        cfg.spiffe.enabled
    );
    let addr = cfg.listen_addr.clone();
    let s: S = Arc::new(State_ {
        cfg,
        cfg_path: path,
        cfg_raw: raw,
        http: reqwest::Client::new(),
        workload: Mutex::new(None),
    });

    let app = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../static/index.html")) }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/bff/web-config", get(web_config))
        .route("/bff/graphql", post(graphql))
        .route("/bff/spiffe", get(spiffe_info))
        .route("/bff/probe", get(probe))
        .route("/bff/subscribe", get(subscribe))
        .with_state(s);
    let l = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(l, app).await?;
    Ok(())
}
