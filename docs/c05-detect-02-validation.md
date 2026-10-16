# C05-DETECT-02 revision 1

## Scope and approval
User approved revision 1 on 2026-10-16 at 14:13 EDT, then requested agent takeover at 15:04 EDT. Base: e1f33d34deb9ec9cdba5a71d29ce8405ede5bdca. Branch: feat/c05-permission-grants. This implements successful application-role and delegated permission-grant detection on UbuntuDesk. D1, C09, ingestion, tenant permissions, Premium activation and TLS settings are excluded. Publication remains separately authorized.

## Detection behavior
The five-field baseline matches receiving client service-principal ObjectID, resource service-principal ObjectID, grant type, individual permission, and consent type. Application consent type is not_applicable. The three baseline tuples were explicitly confirmed by the user. Actor is investigation context, not an authorization key. Consent-to-application events are context and do not substitute for individual grant records.

Nested targets and modified properties are expanded together, grouped by audit event ID and target hash. Secondary targets without grant properties are ignored when a grant-bearing target exists. Events without usable grant properties are retained as parse_error. Missing ID uses a raw-event SHA-256 fallback and remains a parsing error. Blank/literal-null attribution, permissions and delegated consent are retained as errors; multiple distinct client/resource values or conflicting delegated consent are errors. Delegated scopes are split into individual permissions.

The stable alert_key hashes a length-prefixed sequence of event ID, client, resource, grant type, permission, sorted consent values and parse issue. Distinct grants sharing correlationId remain separate; repeated identical keys suppress for 24 hours. Missing-ID fallback is sensitive to raw JSON serialization changes.

Schedule: every 15 minutes, event window -24h to now, index-time lookback -35m, result count greater than zero, local tracking, per-result alerts and suppression. Email, script and webhook actions explicitly disabled. Parse errors trigger investigation alongside grants outside baseline.

## Repeatable validation
Run tools/c05_d2_validate.py from the repository root with a valid sudo session and existing authenticated Splunk CLI session. It evaluates synthetic raw JSON using the same parser and a separate c05d2_fixture_baseline.csv. It writes exact searches, fixture data, expected/actual results and return codes to docs/evidence/c05-detect-02/pipeline.json. No fixture events enter the live entra_id index.

29 fixtures passed. The initial run had one incorrect test expectation: missing consent should retain User.Read, not remove the permission. Initial evidence is preserved in pipeline-initial.json; the corrected full rerun is pipeline.json. Manual screenshots were supplementary and are not substituted for executable evidence.

Scheduler tests use C05D2_negative, C05D2_sequence, C05D2_multi and C05D2_malformed with a separate synthetic policy CSV. The sequence helper waits for first-key firing and repeat suppression, adds a distinct event ID to data without changing search configuration, then waits for one additional firing while the original key stays suppressed. Capture helpers retain scheduler records and fired-alert SIDs. Final acceptance.json is the authoritative completion checklist; absence or a failed check means not ready.

## Rollback and limitations
Root-only backup: /var/backups/c05-detect-02-20261016/before.tgz. An additional pre-d2-savedsearches.conf preserves the file immediately before deployment. Restore only D2 and its named validation stanzas; preserve unrelated edits, metadata, D1 baseline and live suppression history. Reload saved searches and verify service and scheduler recovery. Configuration rollback does not restore runtime suppression history.

Synthetic and retained historical evidence does not establish fresh Entra ingestion. Actual 24-hour suppression expiry is not waited out. The -24h event bound can exclude events ingested more than 24 hours late. The finite Splunk Developer license and pre-existing TLS warning are separately tracked. Premium-dependent sign-in detections remain outside this revision; overall C05 is not complete from this implementation alone.

## Study and portfolio connections
Core first: search pipelines, fields, tables, lookups, saved reports versus alerts, time ranges and scheduled alert conditions. Supporting Power User: spath, stats/eventstats, multivalue fields, eval/case, null handling and reusable test fixtures. Defense Analyst: permission-grant triage, attribution, telemetry gaps and evidence-backed alert disposition.

Automation demonstrated here: deterministic parser regression, scheduler/suppression evidence capture, invariant checks and SHA-256 packaging. Human review, acceptance and publication decisions remain explicit.

## Observed final outcome

All 33 acceptance checks passed, with 29/29 synthetic parser fixtures. D2 completed its normal 15:15 EDT run successfully with zero findings. The scheduled harness demonstrated approved-negative silence, unauthorized-positive firing, repeated-key suppression, a new-key firing without resetting the search, two separately fired permission results, and a malformed-event alert; fired-alert SIDs matched scheduler records. All four temporary schedules were disabled; D2 remains enabled. D1 and all seven C09 schedules succeeded after deployment, with D3a observed at its next 15:20 ten-minute cadence. Targeted reload succeeded; no restart was needed.

The initial all-C09 health check ran before D3a next came due and was retained as acceptance-before-c09-cadence.json. acceptance.json records the completed health gate. Only the polling helper was interrupted during runtime inspection; the unchanged scheduler definitions and data remained active, and final runtime capture verifies the completed sequence.
