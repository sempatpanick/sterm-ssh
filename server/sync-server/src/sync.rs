use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use core_sync::protocol::{SyncPullResponse, SyncPushRequest, SyncPushResponse, SyncedAck};
use serde::Deserialize;

use crate::{auth::verify_bearer, AppState};

#[derive(Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub since: i64,
}

pub async fn pull_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PullQuery>,
) -> Result<Json<SyncPullResponse>, StatusCode> {
    let claims = verify_bearer(&headers, &state.jwt_secret)?;
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (items, server_seq) = db
        .pull_changes(&claims.sub, q.since)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(SyncPullResponse { items, server_seq }))
}

pub async fn push_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SyncPushRequest>,
) -> Result<Json<SyncPushResponse>, StatusCode> {
    let claims = verify_bearer(&headers, &state.jwt_secret)?;
    let mut db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (acks, server_seq) = db
        .push_items(&claims.sub, &req.items)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let synced = acks
        .into_iter()
        .map(|(id, sync_revision)| SyncedAck { id, sync_revision })
        .collect();
    Ok(Json(SyncPushResponse { synced, server_seq }))
}
