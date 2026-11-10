use crate::AppState;
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use spiffe_util::JwtDetails;
use std::sync::Arc;

/// The authenticated caller, placed in request extensions when SPIFFE is enabled.
#[derive(Clone, Debug)]
pub struct Caller(pub JwtDetails);

fn deny(code: StatusCode, msg: impl Into<String>) -> Response {
    (
        code,
        Json(json!({
            "error": msg.into(),
            "hint": "SPIFFE is enabled on this API: present a JWT-SVID for the configured audience as 'Authorization: Bearer <jwt>'",
        })),
    )
        .into_response()
}

pub async fn spiffe_auth(
    State(st): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let cfg = &st.config.spiffe;
    if !cfg.enabled {
        return next.run(req).await;
    }
    let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::to_string)
    else {
        tracing::warn!("rejected request: no credentials");
        return deny(
            StatusCode::UNAUTHORIZED,
            "missing credentials (no Authorization header)",
        );
    };
    let client = match st.workload_client().await {
        Ok(c) => c,
        Err(e) => {
            return deny(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("API cannot reach the SPIFFE Workload API: {e}"),
            )
        }
    };
    let svid = match spiffe_util::validate_jwt(&client, &cfg.audience, &token).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("rejected request: invalid JWT-SVID: {e}");
            st.reset_workload_client().await;
            return deny(StatusCode::UNAUTHORIZED, format!("JWT-SVID rejected: {e}"));
        }
    };
    if !cfg.allowed_ids.is_empty() && !cfg.allowed_ids.contains(&svid.spiffe_id) {
        tracing::warn!("rejected request: {} not authorised", svid.spiffe_id);
        return deny(
            StatusCode::FORBIDDEN,
            format!("{} is authenticated but not authorised", svid.spiffe_id),
        );
    }
    tracing::info!("accepted request from {}", svid.spiffe_id);
    req.extensions_mut().insert(Caller(svid));
    next.run(req).await
}
