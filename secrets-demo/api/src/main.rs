mod auth;
mod config;
mod schema;
mod secrets;

use async_graphql::http::GraphiQLSource;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::{
    extract::{Extension, State},
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AppState {
    pub config: config::Config,
    pub config_path: String,
    pub config_raw: Option<String>,
    workload: Mutex<Option<spiffe_util::WorkloadApiClient>>,
}

impl AppState {
    /// Lazily connect to the Workload API (the agent may start after we do).
    pub async fn workload_client(&self) -> anyhow::Result<spiffe_util::WorkloadApiClient> {
        let mut g = self.workload.lock().await;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let c = spiffe_util::connect(Some(&self.config.spiffe.socket)).await?;
        *g = Some(c.clone());
        Ok(c)
    }
    pub async fn reset_workload_client(&self) {
        *self.workload.lock().await = None;
    }
}

async fn graphql(
    State(schema): State<schema::ApiSchema>,
    caller: Option<Extension<auth::Caller>>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();
    if let Some(Extension(c)) = caller {
        req = req.data(c);
    }
    schema.execute(req).await.into()
}

async fn graphiql() -> impl IntoResponse {
    Html(
        GraphiQLSource::build()
            .endpoint("/graphql")
            .subscription_endpoint("/graphql/ws")
            .finish(),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let loaded = config::load()?;
    tracing::info!(
        "config {} (found={}): scenario={:?} spiffe={} secrets={} dirs={} envPrefixes={}",
        loaded.path,
        loaded.raw.is_some(),
        loaded.config.scenario,
        loaded.config.spiffe.enabled,
        loaded.config.secrets.len(),
        loaded.config.secret_dirs.len(),
        loaded.config.env_prefixes.len()
    );
    let addr = loaded.config.listen_addr.clone();
    let state = Arc::new(AppState {
        config: loaded.config,
        config_path: loaded.path,
        config_raw: loaded.raw,
        workload: Mutex::new(None),
    });
    let schema = schema::build(state.clone());

    // Everything that exposes secrets sits behind the (optional) SPIFFE check.
    let protected = Router::new()
        .route("/graphql", post(graphql))
        .with_state(schema.clone())
        .route_service("/graphql/ws", GraphQLSubscription::new(schema))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::spiffe_auth,
        ));

    let app = Router::new()
        .route("/", get(graphiql))
        .route("/healthz", get(|| async { "ok" }))
        .merge(protected);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
