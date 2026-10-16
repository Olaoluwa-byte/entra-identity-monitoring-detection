# C05-COLLECT-01 revision 1

Status: candidate tested offline; live deployment and independent review pending.

The Free-tier collector requests only directoryAudits. It retains legacy signins checkpoint data without requesting the Premium endpoint. A 24-hour overlap and event-ID cache preserve distinct same-timestamp records and tolerate late arrivals within that overlap. Pagination is restricted to the exact Graph audit endpoint, redirects disabled, and all fetched pages validated before output is appended. Requests retry connection/timeouts, 429 and 5xx within a bounded budget. Errors exit nonzero with sanitized messages.

Output is fsynced before atomic checkpoint replacement. Complete records in the current output recover a crash before checkpoint commit. The collector locks concurrent runs. Partial/unterminated output fails closed for private recovery rather than discarding data. Existing audit checkpoints are migrated and unrelated state keys retained.

## Validation
Run `python3 -m unittest discover -s tests -p 'test_collector.py' -v` from the checkout root. Tests use only synthetic records and mocked HTTP responses; no credentials or tenant access needed. Run `python3 -m py_compile entra_pull.py tests/test_collector.py` for syntax validation.

Initial candidate: 23/23 offline tests passed on the coordinator host. Ubuntu rerun: 23/23 tests passed; py_compile and git diff --check passed. Live deployment pending. No fresh end-to-end ingestion claim.

## Limits
Events that become available earlier than the checkpoint minus 24h can be missed. Initial backfill is six days, subject to source retention. No checkpoint advancement on empty results preserves the original event-watermark semantics but can increase repeated empty scanning. Maximum 200 pages / 100,000 fetched records per run fails explicitly rather than truncating. Current output is scanned for crash recovery; its size influences runtime. Conflicting duplicate IDs within a response fail; previously persisted IDs are treated as immutable.

External logrotate copytruncate does not share the collector lock. Rotation concurrent with append/checkpoint or a crash is not an exactly-once transaction; a later follow-up should coordinate rotation or adopt a transactional spool. A crash with partial output requires manual private repair. No credentials or raw tenant records belong in evidence.

## Deployment and rollback
The service runs the canonical repository file directly. Do not edit that live file while tests are in progress. Prepare an isolated worktree and commit after tests. Before activation, stop the timer, wait for any current oneshot to finish, make a root-only backup of the current collector and checkpoint plus nonsecret configuration, and verify canonical clean/base state. Promote the tested commit, run the service, then restore the original timer enabled/active state. Verify service result, sanitized counts, source/deployed hash, D1/D2/C09 configuration invariance and scheduler health. If deployment fails, restore only the previous collector; do not rewind successful audit output/checkpoints blindly. No Splunk restart is required by this change.

## Learning and automation
Core: index versus sourcetype, event time versus ingestion time, field extraction and searching by event ID. Python automation: mocked HTTP regression cases, nonzero exit status for systemd, bounded retries, atomic checkpoint replacement and repeatable evidence hashes. Independent review and user acceptance remain explicit.
