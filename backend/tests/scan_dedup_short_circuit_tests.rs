//! Integration tests for the same-artifact dedup short-circuit added by #1373.
//!
//! These tests require a PostgreSQL database with migrations applied.
//! Set DATABASE_URL and run:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test scan_dedup_short_circuit_tests -- --ignored
//! ```
//!
//! Why these tests exist
//! ----------------------
//! Release-gate run 26344757642 (security suite, scan-dedup-checksum) failed
//! on two assertions:
//!
//!   1. Second scan on identical bytes returns same scan_id (no duplicate row)
//!   2. Per-artifact scan list for B contains exactly one completed scan
//!
//! Both failures trace back to `prepare_artifact_scan` inserting a new
//! `running` placeholder row on every call, without first checking whether
//! the artifact already had a completed scan for the same checksum +
//! scan_type. The placeholder then fell through `scan_artifact_inner`'s
//! `should_skip_reuse_for_same_artifact` branch, which (pre-fix) skipped the
//! reuse-copy path AND ran a fresh scan, leaving two completed rows behind.
//!
//! The fix adds `find_existing_scan_for_artifact` (scan_result_service.rs),
//! short-circuits `prepare_artifact_scan` when an existing scan is found, and
//! teaches `scan_artifact_inner` to no-op when the matched reusable scan is
//! for the current artifact.
//!
//! Test coverage
//! -------------
//! * `find_existing_scan_for_artifact` returns Some for a matching artifact +
//!   checksum + scan_type within the TTL window.
//! * Returns None when scan_type does not match.
//! * Returns None when checksum does not match (different bytes).
//! * Returns None when the scan is for a different artifact (the cross-
//!   artifact dedup case is `find_reusable_scan`'s job, not this method's).
//! * Returns None when the scan is older than the TTL.
//! * Returns None when only a `running` row exists (status must be completed).

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::scan_result_service::ScanResultService;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-dedup-short-circuit-{}", id);
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("dedup-short-circuit-{}", id))
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("failed to create test repository");
    id
}

async fn insert_artifact(pool: &PgPool, repo_id: Uuid, name: &str, checksum: &str) -> Uuid {
    let id = Uuid::new_v4();
    let path = format!("{}/{}", repo_id, name);
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256,
                               content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream', $4, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(name)
    .bind(&path)
    .bind(1024_i64)
    .bind(checksum)
    .execute(pool)
    .await
    .expect("failed to insert test artifact");
    id
}

/// Insert a completed scan_result row with the given checksum + scan_type +
/// status. `completed_at_offset_days` shifts the completed_at backwards by
/// that many days so the TTL-boundary case can be exercised.
async fn insert_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    checksum: &str,
    scan_type: &str,
    status: &str,
    completed_at_offset_days: i32,
) -> Uuid {
    let scan_id = Uuid::new_v4();
    let completed_at = if status == "completed" {
        format!("NOW() - INTERVAL '{} days'", completed_at_offset_days)
    } else {
        "NULL".to_string()
    };
    let query = format!(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status,
            findings_count, critical_count, high_count, medium_count, low_count, info_count,
            scanner_version, started_at, completed_at, checksum_sha256
        )
        VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 0, 0, 0,
                'trivy-0.50.0', NOW(), {}, $6)
        "#,
        completed_at,
    );
    sqlx::query(&query)
        .bind(scan_id)
        .bind(artifact_id)
        .bind(repo_id)
        .bind(scan_type)
        .bind(status)
        .bind(checksum)
        .execute(pool)
        .await
        .expect("failed to insert scan_result fixture");
    scan_id
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query(
        "DELETE FROM scan_findings WHERE scan_result_id IN \
         (SELECT id FROM scan_results WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .execute(pool)
    .await
    .ok();
    sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
}

const CHECKSUM_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHECKSUM_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------------------
// Happy path: existing scan is returned
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_some_for_matching_artifact_and_checksum() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30)
        .await
        .expect("query must not error");

    let row = found.expect("must find the completed scan for this artifact");
    assert_eq!(
        row.id, scan_id,
        "must return the existing scan's id verbatim"
    );
    assert_eq!(row.artifact_id, artifact_id);
    assert_eq!(row.status, "completed");

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: different artifact => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_for_different_artifact_same_checksum() {
    // Two artifacts sharing one checksum (byte-identical uploads).
    // `find_existing_scan_for_artifact` scopes by artifact_id, so artifact A's
    // completed scan must NOT be returned when querying for artifact B. That
    // cross-artifact dedup is `find_reusable_scan`'s job.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_a = insert_artifact(&pool, repo_id, "a.tgz", CHECKSUM_A).await;
    let artifact_b = insert_artifact(&pool, repo_id, "b.tgz", CHECKSUM_A).await;
    let _scan_a = insert_scan(
        &pool,
        artifact_a,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_b, CHECKSUM_A, "dependency", 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT match artifact A's scan when querying for artifact B"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: different checksum => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_when_checksum_differs() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_B, "dependency", 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT match when the requested checksum differs from the stored one"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: different scan_type => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_when_scan_type_differs() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "image", 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT match when scan_type differs (dependency scan != image scan)"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: still running, never completed => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_for_running_scan() {
    // A `running` row must not satisfy the "already scanned" check. Otherwise
    // a stuck or in-flight scan would short-circuit a retry, and the artifact
    // would never get a real completed scan.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "running",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT short-circuit on a `running` row; only completed scans count"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: scan is older than the TTL window => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_when_scan_is_older_than_ttl() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    // Completed 40 days ago; with ttl_days = 30 the row must be excluded so
    // stale artifacts get rescanned to pick up freshly-published advisories.
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        40,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT short-circuit when the existing scan is older than the TTL window"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Most-recent wins: latest completed scan is returned when there are several.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_most_recent_when_multiple_completed_exist() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;

    // Two completed scans for the same artifact + checksum + scan_type:
    // older completed first, then a newer one. The newer scan_id must win.
    let _old_scan = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        5,
    )
    .await;
    let new_scan = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30)
        .await
        .expect("query must not error")
        .expect("must find a completed scan");

    assert_eq!(
        found.id, new_scan,
        "must return the most-recent completed scan (ORDER BY completed_at DESC)"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Concurrent race: orphan placeholder + completed sibling + two trigger_scan
// calls in flight at once.
//
// Real-world setup that produced #1373:
//   1. A trigger_scan call inserted a `running` placeholder but the worker
//      never finished (process killed, scanner crashed, etc.). The placeholder
//      is now an orphan in `running` state, waiting for the stuck-scan janitor.
//   2. A later trigger_scan call for the same artifact + bytes successfully
//      ran and inserted a `completed` row.
//   3. Two more trigger_scan calls land concurrently on the same artifact.
//
// Without the #1373 short-circuit, step 3 inserts two more `running`
// placeholders and runs two redundant scans, leaving four+ completed rows
// for one artifact. With the fix, both concurrent calls must:
//   a. Return the same scan_id (the completed sibling's id, not a new UUID).
//   b. Leave the orphan placeholder convertible by the same dedup machinery
//      (convert_to_reused) that scan_artifact_inner runs against any
//      placeholder that races with a sibling completion.
//
// This test commits the orphan + sibling via SQL, races two
// `find_existing_scan_for_artifact` calls (the same DB call
// `prepare_artifact_scan` performs to populate the trigger response), then
// drives `convert_to_reused` on the orphan to assert the terminal state.
//
// Note: a full end-to-end race through `ScannerService::prepare_artifact_scan`
// would require wiring an `AdvisoryClient`, storage backend, and per-scanner
// stubs into a real `ScannerService`. We deliberately go through the same
// `ScanResultService` calls `prepare_artifact_scan` makes per scanner, which
// is where the dedup contract lives. The orchestration above those calls is
// covered by the pure-function unit tests in `scanner_service::tests`.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database; cleanup is intentionally skipped so a `cargo test --ignored` run can verify state against the live DB.
async fn test_concurrent_trigger_scan_race_returns_same_scan_id_and_converts_orphan() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "race.tgz", CHECKSUM_A).await;

    // Pre-existing completed scan (the "winner" both concurrent triggers must
    // short-circuit to). Use a recent completed_at so the TTL window contains
    // it. Inserted before the orphan so ORDER BY completed_at DESC still picks
    // it: completed_at = NOW().
    let winner_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    // Pre-existing orphan placeholder from a previous trigger that never
    // finished. status = 'running', completed_at = NULL. This is the row that
    // must end up converted (NOT left stuck for the janitor).
    let orphan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "running",
        0,
    )
    .await;

    let svc = std::sync::Arc::new(ScanResultService::new(pool.clone()));

    // Race two find_existing_scan_for_artifact calls. This is the DB call
    // `prepare_artifact_scan` issues per scanner before deciding whether to
    // short-circuit or insert a placeholder. Both must return Some(winner_id);
    // racing them concurrently exercises the same path two real trigger_scan
    // requests would take.
    let svc_a = svc.clone();
    let svc_b = svc.clone();
    let (res_a, res_b) = tokio::join!(
        async move {
            svc_a
                .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30)
                .await
        },
        async move {
            svc_b
                .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30)
                .await
        },
    );

    let row_a = res_a
        .expect("trigger A: query must not error")
        .expect("trigger A: must find the completed sibling");
    let row_b = res_b
        .expect("trigger B: query must not error")
        .expect("trigger B: must find the completed sibling");

    // Assertion 1: both concurrent triggers return the same scan_id (the
    // existing completed scan, NOT a freshly minted placeholder UUID). This is
    // the contract release-gate run 26344757642 originally broke.
    assert_eq!(
        row_a.id, winner_id,
        "concurrent trigger A must short-circuit to the existing completed scan"
    );
    assert_eq!(
        row_b.id, winner_id,
        "concurrent trigger B must short-circuit to the existing completed scan"
    );
    assert_eq!(
        row_a.id, row_b.id,
        "two concurrent trigger_scan calls on identical bytes must return the same scan_id"
    );

    // Drive the orphan-conversion path that scan_artifact_inner runs when
    // find_reusable_scan matches a sibling completed scan for the same
    // artifact. This is the production code path for cleaning up the orphan
    // placeholder a previous trigger left behind.
    let converted = svc
        .convert_to_reused(orphan_id, winner_id, artifact_id)
        .await
        .expect("orphan conversion must succeed");

    // Assertion 2: orphan is now in a terminal state and points at the winner.
    assert_eq!(
        converted.id, orphan_id,
        "convert_to_reused must operate on the orphan row (not insert a new one)"
    );
    assert_eq!(
        converted.status, "completed",
        "orphan must be flipped from 'running' to 'completed' so the stuck-scan janitor never has to reap it"
    );
    assert!(
        converted.is_reused,
        "converted orphan must be marked is_reused = true"
    );
    assert_eq!(
        converted.source_scan_id,
        Some(winner_id),
        "converted orphan must point source_scan_id at the winner"
    );

    // Re-read from the DB to confirm the UPDATE landed in shared storage, not
    // just in the returned struct. This catches a regression where
    // convert_to_reused might return a fabricated row without committing.
    // Using untyped `sqlx::query` (not `query!`) so the test compiles without
    // a SQLX_OFFLINE cache entry; the assertions below are the contract.
    let reloaded: (String, bool, Option<Uuid>) =
        sqlx::query_as("SELECT status, is_reused, source_scan_id FROM scan_results WHERE id = $1")
            .bind(orphan_id)
            .fetch_one(&pool)
            .await
            .expect("orphan row must still exist after conversion");
    assert_eq!(reloaded.0, "completed");
    assert!(reloaded.1);
    assert_eq!(reloaded.2, Some(winner_id));

    // Cleanup is intentionally skipped so a `cargo test --ignored` run leaves
    // the converted row, the winner, the artifact, and the repo in place for
    // manual inspection against a real DB (e.g., to verify the orphan row's
    // completed_at was set by NOW() rather than copied from the source). Tests
    // that need a clean slate can drop the repo by key prefix
    // `test-dedup-short-circuit-`.
    let _ = repo_id; // suppress unused-binding warning under the skip-cleanup path
}
