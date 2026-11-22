use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use core_crypto::kdf::KdfParams;
use core_sync::protocol::{
    AccountProfile, AuthResponse, ChangePasswordRequest, DeleteAccountRequest, LoginRequest,
    RegisterRequest, SaltRequest, SaltResponse,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
}

fn issue_token(account_id: &str, email: &str, secret: &str) -> Result<String, StatusCode> {
    let exp = (Utc::now().timestamp() + 60 * 60 * 24 * 30) as usize; // 30 days
    let claims = Claims {
        sub: account_id.to_string(),
        email: email.to_string(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn verify_bearer(headers: &axum::http::HeaderMap, secret: &str) -> Result<Claims, StatusCode> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(data.claims)
}

/// Returns the account's KDF salt & params, or a deterministic dummy salt on unknown email
/// to mitigate account enumeration.
pub async fn get_salt(
    State(state): State<AppState>,
    Json(req): Json<SaltRequest>,
) -> Result<Json<SaltResponse>, StatusCode> {
    let email = req.email.trim().to_lowercase();
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Ok(Some(acc)) = db.find_account_by_email(&email) {
        return Ok(Json(SaltResponse {
            kdf_salt_b64: acc.kdf_salt_b64,
            kdf_params: acc.kdf_params,
        }));
    }

    let mut hasher = Sha256::new();
    hasher.update(state.salt_pepper.as_bytes());
    hasher.update(email.as_bytes());
    let dummy_salt = hasher.finalize();

    Ok(Json(SaltResponse {
        kdf_salt_b64: B64.encode(dummy_salt),
        kdf_params: KdfParams::default(),
    }))
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, String)> {
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') || req.auth_key_b64.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "invalid registration payload".into()));
    }

    let salt = SaltString::generate(&mut OsRng);
    let auth_hash = Argon2::default()
        .hash_password(req.auth_key_b64.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    let account_id = Uuid::now_v7().to_string();
    let now = Utc::now().timestamp_millis();

    {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db lock".into()))?;
        if db
            .find_account_by_email(&email)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .is_some()
        {
            return Err((StatusCode::CONFLICT, "email already registered".into()));
        }
        db.create_account(
            &account_id,
            &email,
            &auth_hash,
            &req.kdf_salt_b64,
            &req.kdf_params,
            &req.wrapped_dek_b64,
            now,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let token = issue_token(&account_id, &email, &state.jwt_secret)
        .map_err(|s| (s, "token error".into()))?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            account_id,
            email,
            access_token: token,
            kdf_salt_b64: req.kdf_salt_b64,
            kdf_params: req.kdf_params,
            wrapped_dek_b64: req.wrapped_dek_b64,
        }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let email = req.email.trim().to_lowercase();
    let acc = {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db lock".into()))?;
        db.find_account_by_email(&email)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "invalid credentials".into()))?
    };

    let parsed_hash = PasswordHash::new(&acc.auth_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "corrupt hash".into()))?;

    Argon2::default()
        .verify_password(req.auth_key_b64.as_bytes(), &parsed_hash)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid credentials".into()))?;

    let token = issue_token(&acc.id, &acc.email, &state.jwt_secret)
        .map_err(|s| (s, "token error".into()))?;

    Ok(Json(AuthResponse {
        account_id: acc.id,
        email: acc.email,
        access_token: token,
        kdf_salt_b64: acc.kdf_salt_b64,
        kdf_params: acc.kdf_params,
        wrapped_dek_b64: acc.wrapped_dek_b64,
    }))
}

pub async fn get_me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AccountProfile>, StatusCode> {
    let claims = verify_bearer(&headers, &state.jwt_secret)?;
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (acc, created_at) = db
        .find_account_by_id(&claims.sub)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let item_count = db
        .count_active_items(&acc.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AccountProfile {
        account_id: acc.id,
        email: acc.email,
        created_at,
        item_count,
    }))
}

pub async fn change_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let claims = verify_bearer(&headers, &state.jwt_secret)
        .map_err(|s| (s, "unauthorized".into()))?;

    let acc = {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db lock".into()))?;
        db.find_account_by_id(&claims.sub)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "account not found".into()))?
            .0
    };

    let parsed_hash = PasswordHash::new(&acc.auth_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "corrupt hash".into()))?;
    Argon2::default()
        .verify_password(req.current_auth_key_b64.as_bytes(), &parsed_hash)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "current password is incorrect".into()))?;

    let salt = SaltString::generate(&mut OsRng);
    let new_auth_hash = Argon2::default()
        .hash_password(req.new_auth_key_b64.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_string();

    {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db lock".into()))?;
        db.update_account_credentials(
            &acc.id,
            &new_auth_hash,
            &req.new_kdf_salt_b64,
            &req.new_kdf_params,
            &req.new_wrapped_dek_b64,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let token = issue_token(&acc.id, &acc.email, &state.jwt_secret)
        .map_err(|s| (s, "token error".into()))?;

    Ok(Json(AuthResponse {
        account_id: acc.id,
        email: acc.email,
        access_token: token,
        kdf_salt_b64: req.new_kdf_salt_b64,
        kdf_params: req.new_kdf_params,
        wrapped_dek_b64: req.new_wrapped_dek_b64,
    }))
}

pub async fn delete_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let claims = verify_bearer(&headers, &state.jwt_secret)
        .map_err(|s| (s, "unauthorized".into()))?;

    let acc = {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db lock".into()))?;
        db.find_account_by_id(&claims.sub)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "account not found".into()))?
            .0
    };

    let parsed_hash = PasswordHash::new(&acc.auth_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "corrupt hash".into()))?;
    Argon2::default()
        .verify_password(req.current_auth_key_b64.as_bytes(), &parsed_hash)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "password is incorrect".into()))?;

    let mut db = state
        .db
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db lock".into()))?;
    db.delete_account(&acc.id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
