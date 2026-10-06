mod strict_read_support;

#[tokio::test]
async fn strict_read_wire_query_timeout_discards_protected_backend() {
    strict_read_support::protocol::strict_wire_query_timeout_discards_protected_backend().await;
}

#[tokio::test]
async fn strict_read_wire_active_cancel_releases_locked_backend() {
    strict_read_support::protocol::strict_wire_active_cancel_releases_locked_backend().await;
}

#[tokio::test]
async fn strict_read_bootstrap_unsafe_string_mode_has_no_parameter_side_effects() {
    strict_read_support::cases::strict_bootstrap_rejects_unsafe_string_mode_before_parameter_sync()
        .await;
}

#[tokio::test]
async fn strict_read_wire_partial_packets_and_unfinished_message_budget() {
    strict_read_support::protocol::strict_wire_partial_packets_and_unfinished_message_budget()
        .await;
}

#[tokio::test]
async fn strict_read_wire_extended_controls_and_idle_commit() {
    strict_read_support::protocol::strict_wire_extended_controls_and_idle_commit().await;
}

#[tokio::test]
async fn strict_read_protocol_reload_preserves_mode_and_manifest() {
    strict_read_support::cases::strict_reload_keeps_process_policy_and_manifest().await;
}

#[tokio::test]
async fn strict_read_baseline_direct_app_dml_and_privileges() {
    strict_read_support::cases::assert_app_dml_and_privileges(
        strict_read_support::fixture().postgres_port,
    )
    .await;
}

#[tokio::test]
async fn strict_read_baseline_write_proxy_dml_and_privileges() {
    strict_read_support::cases::assert_app_dml_and_privileges(
        strict_read_support::fixture().write_port,
    )
    .await;
}

#[tokio::test]
async fn strict_read_protocol_simple_select_returns_data_row() {
    strict_read_support::cases::strict_simple_select().await;
}

#[tokio::test]
async fn strict_read_protocol_simple_insert_is_denied_without_backend_change() {
    strict_read_support::cases::strict_simple_insert_is_denied().await;
}

#[tokio::test]
async fn strict_read_protocol_simple_positive_and_denial_matrix() {
    strict_read_support::cases::strict_simple_matrix().await;
}

#[tokio::test]
async fn strict_read_protocol_driver_prepared_and_failed_transaction_recovery() {
    strict_read_support::cases::strict_driver_prepared_transactions().await;
}

#[tokio::test]
async fn strict_read_wire_flush_sync_and_named_statement_reprepare() {
    strict_read_support::protocol::strict_wire_flush_returns_before_sync_and_named_statement_survives_epoch_change().await;
}

#[tokio::test]
async fn strict_read_wire_suspended_portal_survives_statement_close() {
    strict_read_support::protocol::strict_wire_resumes_suspended_portal_after_closing_its_statement().await;
}

#[tokio::test]
async fn strict_read_wire_extended_error_discards_until_sync() {
    strict_read_support::protocol::strict_wire_error_discards_until_sync_then_returns_one_ready()
        .await;
}

#[tokio::test]
async fn strict_read_wire_explicit_error_state_requires_rollback() {
    strict_read_support::protocol::strict_wire_explicit_transaction_stays_failed_until_rollback()
        .await;
}

#[tokio::test]
async fn strict_read_wire_denies_fastpath_and_orphan_copy() {
    strict_read_support::protocol::strict_wire_denies_fastpath_and_orphan_copy_data().await;
}

#[tokio::test]
async fn strict_read_wire_unknown_close_is_idempotent() {
    strict_read_support::protocol::strict_wire_unknown_close_is_idempotent().await;
}

#[tokio::test]
async fn strict_read_wire_lost_backend_before_sync_fails_closed() {
    strict_read_support::protocol::strict_wire_lost_backend_before_sync_fails_closed_and_reconnects().await;
}

#[tokio::test]
async fn strict_read_wire_cancel_request_stays_within_strict_session() {
    strict_read_support::protocol::strict_wire_cancel_request_does_not_escape_strict_session()
        .await;
}
