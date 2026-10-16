# C05-ALERTS-01 revision 1

User approved local implementation, UbuntuDesk deployment and validation on 2026-10-16 at 13:16 EDT. Base: `9e7d5e1d7c5bf3598984b8d69b58ea23e548a4ee`; branch: `fix/c05-alert-trigger`. See the preserved approved brief and evidence for the final acceptance result.

## Observed result

All 25 acceptance checks passed. All eight pipeline fixtures passed after private reauthentication. Scheduled positive, negative, repeat-ID, distinct-ID and multi-result tests passed with matching tracked SIDs. The normal live 13:30 EDT run succeeded with zero results and no new tracked alert. All seven C09 searches resumed successfully after restart. Temporary test scheduling is disabled. See acceptance.json for exact evidence and timestamps.

## Change and cause

The source and live stanza used three REST-style field names in savedsearches.conf. Splunk 10.4.3 btool flagged those keys and used counttype=always. The repair uses the configuration keys counttype/relation/quantity. REST still reports the equivalent policy as alert_type/alert_comparator/alert_threshold; those names are valid REST fields, not valid configuration-file keys here.

Explicit alert.digest_mode=0 restores the intended per-result correlationId suppression. The default batch mode did not implement that intended policy. Email, script and webhook actions are explicitly off. Detection SPL is byte-identical to base; cadence, event/index windows, suppression period, live lookup and permissions are preserved.

## Execution and reproducibility

These scripts are bound to this approved task and lab paths. They are an automation foundation, not an unattended deployment service. Do not rerun installation against another base or reset suppression state to get passing tests.

1. `sudo -n python3 tools/c05_capture_before.py` captured private rollback files and sanitized before evidence.
2. `sudo -n python3 tools/c05_install.py` asserted the base hashes, repaired the target stanza and created isolated validation resources.
3. REST reload attempts did not activate the changed settings. `sudo -n systemctl restart Splunkd` was required; service returned active. The restart invalidated the prior Splunk CLI session. The user authenticated privately. The interrupted fixture attempt is retained as pipeline-auth-attempt.json; the complete rerun is pipeline.json.
4. `sudo -n python3 tools/c05_test_pipeline.py` ran eight extracted-field fixtures using a separate baseline lookup. Approved actor/app, failed operation and unrelated operation are negative cases; unknown update/create, wrong actor, app-actor fallback and unknown actor are positive cases.
5. `sudo -n python3 tools/c05_capture_policy.py repeated-A` recorded first and repeat scheduled runs. A fixture-only change added correlation ID B alongside A; the timestamp and unchanged search-configuration hash are in policy-new-id-change.json. The early added-B snapshot preceded the next dispatch; confirmed-B contains the completed dispatch.
6. `sudo -n python3 tools/c05_capture_policy.py confirmed-B` captured scheduled empty, repeated-ID, distinct-ID and multi-result behavior with local fired-alert SIDs. The search definition was unchanged throughout each suppression sequence.
7. `sudo -n python3 tools/c05_disable_tests.py` disabled all three temporary schedules through the local Splunk API. The harness and synthetic lookups remain for review. API response bodies contain broad configuration defaults, so cleanup evidence preserves response hashes and HTTP status plus an explicit readback, instead of embedding entire responses. The original capture stays with the private rollback archive.
8. After the normal 13:30 live run, `sudo -n python3 tools/c05_finalize.py` checks all required evidence, live scheduler recovery, C09 scheduler recovery, service health, configuration, lookup/metadata preservation and cleanup. A failed assertion means the task is not ready.

## Evidence interpretation

The scheduler reports per-result fired/suppressed counts; the REST fired-alert listing groups tracking entries by dispatch. Thus a two-result firing can have fired=2 and one REST SID row. Compare SIDs and scheduler counts together.

Synthetic fixture tests exercise the detection pipeline after field extraction. They do not prove fresh Graph ingestion, JSON extraction or the index-time selector. The isolated scheduler searches exercise the repaired trigger policy on deterministic result rows. The normal live schedule provides the deployed integration check. No new tenant application, credential, permission or subscription was created.

The configured suppression duration remains 24 hours. Repeat suppression was observed within that interval; expiry was not waited out. Changing a saved search may reset runtime suppression history and permit repeat alerts. No live suppression state was manually deleted. Restoring configuration does not guarantee exact restoration of runtime suppression history.

## Rollback and limits

Private root-only backup: `/var/backups/c05-alerts-01-20261016/before.tgz`, mode 0600. Restore only the target stanza from its preserved savedsearches.conf, preserve unrelated current stanzas, reload/restart if required, then verify service and scheduler recovery. The archive also preserves the existing lookup, metadata and applicable alert-actions directory when present. Rollback was not exercised after a successful repair.

TLS hostname validation remains a pre-existing issue outside this task. No push, PR, merge, tag or release is authorized. Implementation readiness requires independent review and user acceptance; the broader C05 project remains In Progress.
