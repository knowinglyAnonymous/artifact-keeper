//! Email subscription CRUD API.
//!
//! Replaces the email side of the v1.1.x `/api/v1/repositories/:key/notifications`
//! routes (deleted in #920). Operators manage email subscriptions per-repo
//! (or globally with `repository_id IS NULL`) through this surface; the
//! delivery side lives in [`crate::services::email_dispatcher`].
//!
//! Auth contract: every mutation requires `write:repositories` scope AND
//! `can_access_repo` on the target repository. Listing requires the same
//! scope. Global (NULL repo_id) subscriptions require admin.

use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::repository_service::RepositoryService;

/// Defense-in-depth cap on how many recipient addresses one subscription
/// can fan out to. Old `notification_dispatcher` had no cap (security M1);
/// even with this in place, a malicious operator could create N subscriptions
/// each at this size, so per-event rate limiting is the proper backstop.
/// 32 covers realistic ops mailing lists (oncall + secondary + 2-3 humans)
/// with a safety margin.
const MAX_RECIPIENTS_PER_SUBSCRIPTION: usize = 32;

/// Allowed event-type tokens. The dispatcher does substring filtering against
/// this list when matching events to subscriptions; rejecting unknown tokens
/// at write time prevents a typo from silently dropping all notifications.
const VALID_EVENT_TYPES: &[&str] = &[
    "artifact.uploaded",
    "artifact.deleted",
    "scan.completed",
    "scan.failed",
    "repository.created",
    "repository.deleted",
    "license.violation",
    "vulnerability.detected",
];

pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:key/email-subscriptions",
            get(list_subscriptions).post(create_subscription),
        )
        .route(
            "/:key/email-subscriptions/:subscription_id",
            delete(delete_subscription),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateEmailSubscriptionRequest {
    /// Email addresses to deliver matching events to. Bounded length;
    /// see `MAX_RECIPIENTS_PER_SUBSCRIPTION` for the operator-facing limit.
    pub recipients: Vec<String>,
    /// Event-type tokens to listen for. Must be drawn from `VALID_EVENT_TYPES`.
    pub event_types: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EmailSubscriptionResponse {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub recipients: Vec<String>,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EmailSubscriptionListResponse {
    pub subscriptions: Vec<EmailSubscriptionResponse>,
}

/// Require that the caller can mutate email subscriptions on this repository.
///
/// 1. Authenticated.
/// 2. `write:repositories` scope (or admin).
/// 3. `can_access_repo` on the target repo.
///
/// 404 (not 403) on the access-denied case to avoid leaking the existence
/// of repo ids; same pattern as the SBOM endpoints (#903 F6).
fn require_repo_write(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    if auth.is_admin {
        return Ok(auth);
    }
    auth.require_scope("write:repositories")?;
    Ok(auth)
}

/// Validate the supplied event-type tokens against [`VALID_EVENT_TYPES`].
/// Returns `Err(Validation)` listing unknown tokens; doing this at write
/// time prevents typos from silently dropping notifications at delivery.
pub(crate) fn validate_event_types(event_types: &[String]) -> Result<()> {
    if event_types.is_empty() {
        return Err(AppError::Validation(
            "event_types must contain at least one entry".to_string(),
        ));
    }
    let unknown: Vec<&String> = event_types
        .iter()
        .filter(|t| !VALID_EVENT_TYPES.contains(&t.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(AppError::Validation(format!(
            "Unknown event types: {:?}. Valid: {:?}",
            unknown, VALID_EVENT_TYPES
        )));
    }
    Ok(())
}

/// Validate the supplied recipient list.
///
/// - Non-empty
/// - Bounded length (`MAX_RECIPIENTS_PER_SUBSCRIPTION`)
/// - Each entry passes minimal syntactic checks (contains `@`, non-empty
///   local + domain parts). This is intentionally light; SMTP delivery
///   itself is the canonical validator. The goal here is to reject
///   obvious junk before it reaches the database.
pub(crate) fn validate_recipients(recipients: &[String]) -> Result<()> {
    if recipients.is_empty() {
        return Err(AppError::Validation(
            "recipients must contain at least one address".to_string(),
        ));
    }
    if recipients.len() > MAX_RECIPIENTS_PER_SUBSCRIPTION {
        return Err(AppError::Validation(format!(
            "recipients count ({}) exceeds maximum of {}",
            recipients.len(),
            MAX_RECIPIENTS_PER_SUBSCRIPTION
        )));
    }
    for addr in recipients {
        let trimmed = addr.trim();
        let bad = trimmed.is_empty()
            || !trimmed.contains('@')
            || trimmed.starts_with('@')
            || trimmed.ends_with('@')
            || trimmed.split('@').filter(|p| !p.is_empty()).count() != 2;
        if bad {
            return Err(AppError::Validation(format!(
                "recipient '{}' is not a valid email address",
                trimmed
            )));
        }
    }
    Ok(())
}

/// List the email subscriptions configured on a repository.
#[utoipa::path(
    get,
    path = "/{key}/email-subscriptions",
    context_path = "/api/v1/repositories",
    tag = "email_subscriptions",
    params(("key" = String, Path, description = "Repository key")),
    responses(
        (status = 200, description = "List of email subscriptions", body = EmailSubscriptionListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_subscriptions(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<EmailSubscriptionListResponse>> {
    let auth = require_repo_write(auth)?;
    let repo = RepositoryService::new(state.db.clone())
        .get_by_key(&key)
        .await?;
    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

    let rows = sqlx::query(
        r#"
        SELECT id, repository_id, recipients, event_types, enabled,
               created_at, updated_at
        FROM email_subscriptions
        WHERE repository_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let subscriptions: Vec<EmailSubscriptionResponse> = rows
        .into_iter()
        .map(|r| EmailSubscriptionResponse {
            id: r.get("id"),
            repository_id: r.get("repository_id"),
            recipients: r.get("recipients"),
            event_types: r.get("event_types"),
            enabled: r.get("enabled"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        })
        .collect();

    Ok(Json(EmailSubscriptionListResponse { subscriptions }))
}

/// Create an email subscription scoped to a repository.
#[utoipa::path(
    post,
    path = "/{key}/email-subscriptions",
    context_path = "/api/v1/repositories",
    tag = "email_subscriptions",
    params(("key" = String, Path, description = "Repository key")),
    request_body = CreateEmailSubscriptionRequest,
    responses(
        (status = 201, description = "Subscription created", body = EmailSubscriptionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_subscription(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(body): Json<CreateEmailSubscriptionRequest>,
) -> Result<Json<EmailSubscriptionResponse>> {
    let auth = require_repo_write(auth)?;
    let repo = RepositoryService::new(state.db.clone())
        .get_by_key(&key)
        .await?;
    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

    validate_event_types(&body.event_types)?;
    validate_recipients(&body.recipients)?;

    let row = sqlx::query(
        r#"
        INSERT INTO email_subscriptions
            (repository_id, recipients, event_types, enabled)
        VALUES ($1, $2, $3, $4)
        RETURNING id, repository_id, recipients, event_types, enabled,
                  created_at, updated_at
        "#,
    )
    .bind(repo.id)
    .bind(&body.recipients)
    .bind(&body.event_types)
    .bind(body.enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(EmailSubscriptionResponse {
        id: row.get("id"),
        repository_id: row.get("repository_id"),
        recipients: row.get("recipients"),
        event_types: row.get("event_types"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }))
}

/// Delete an email subscription by id.
#[utoipa::path(
    delete,
    path = "/{key}/email-subscriptions/{subscription_id}",
    context_path = "/api/v1/repositories",
    tag = "email_subscriptions",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("subscription_id" = Uuid, Path, description = "Subscription ID")
    ),
    responses(
        (status = 204, description = "Subscription deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Subscription or repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_subscription(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, subscription_id)): Path<(String, Uuid)>,
) -> Result<axum::http::StatusCode> {
    let auth = require_repo_write(auth)?;
    let repo = RepositoryService::new(state.db.clone())
        .get_by_key(&key)
        .await?;
    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

    let result =
        sqlx::query("DELETE FROM email_subscriptions WHERE id = $1 AND repository_id = $2")
            .bind(subscription_id)
            .bind(repo.id)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Email subscription '{}' not found on repository '{}'",
            subscription_id, key
        )));
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(OpenApi)]
#[openapi(
    paths(list_subscriptions, create_subscription, delete_subscription),
    components(schemas(
        CreateEmailSubscriptionRequest,
        EmailSubscriptionResponse,
        EmailSubscriptionListResponse,
    )),
    tags((name = "email_subscriptions", description = "Per-repository email subscription management"))
)]
pub struct EmailSubscriptionsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_event_types_accepts_known_tokens() {
        validate_event_types(&[
            "artifact.uploaded".to_string(),
            "scan.completed".to_string(),
        ])
        .expect("known event types must validate");
    }

    #[test]
    fn test_validate_event_types_rejects_unknown_token() {
        let err = validate_event_types(&["nope.unknown".to_string()]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("nope.unknown")),
            other => panic!("expected Validation error, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_event_types_rejects_empty() {
        let err = validate_event_types(&[]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_accepts_simple_addresses() {
        validate_recipients(&[
            "ops@example.com".to_string(),
            "team@example.org".to_string(),
        ])
        .expect("syntactically valid addresses must pass");
    }

    #[test]
    fn test_validate_recipients_rejects_empty() {
        let err = validate_recipients(&[]).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn test_validate_recipients_rejects_over_cap() {
        let many: Vec<String> = (0..MAX_RECIPIENTS_PER_SUBSCRIPTION + 1)
            .map(|i| format!("u{}@example.com", i))
            .collect();
        let err = validate_recipients(&many).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("exceeds maximum")),
            other => panic!("expected Validation error, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_recipients_rejects_malformed() {
        let cases = [
            "no-at-sign",
            "@no-local-part",
            "no-domain@",
            "two@at@signs",
            "  ",
        ];
        for bad in cases {
            let err = validate_recipients(&[bad.to_string()]).unwrap_err();
            assert!(
                matches!(err, AppError::Validation(_)),
                "expected Validation for {:?}",
                bad
            );
        }
    }

    #[test]
    fn test_max_recipients_per_subscription_is_documented_constant() {
        assert_eq!(MAX_RECIPIENTS_PER_SUBSCRIPTION, 32);
    }
}
