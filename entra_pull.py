#!/usr/bin/env python3
"""Collect directory audits on Entra Free; never request Premium sign-in logs.

At-least-once source collection with a 24h overlap and event-ID deduplication.
Complete current output records also recover a crash before checkpoint commit.
Concurrent external copytruncate rotation is not an exactly-once transaction.
"""
import datetime as dt
import email.utils
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from urllib.parse import urlsplit

import requests

UTC = dt.timezone.utc
AUDIT_URL = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits'
OVERLAP = dt.timedelta(hours=24)
RETRIES = 4
MAX_PAGES = 200
MAX_EVENTS = 100000


class CollectionError(RuntimeError):
    pass


def timestamp(value):
    if not isinstance(value, str):
        raise CollectionError('invalid timestamp type')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise CollectionError('invalid timestamp') from None
    if parsed.tzinfo is None:
        raise CollectionError('timestamp has no timezone')
    return parsed.astimezone(UTC)


def iso(value):
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z')


def retry_delay(response, attempt):
    value = response.headers.get('Retry-After', '')
    try:
        delay = float(value)
    except ValueError:
        try:
            delay = (email.utils.parsedate_to_datetime(value) - dt.datetime.now(UTC)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            delay = 2 ** attempt
    if delay > 300:
        raise CollectionError('Retry-After exceeds run budget; retry next timer cycle')
    return max(0, delay)


def request_json(method, url, *, sleep=time.sleep, **kwargs):
    for attempt in range(RETRIES + 1):
        try:
            response = method(url, timeout=60, allow_redirects=False, **kwargs)
        except (requests.Timeout, requests.ConnectionError):
            if attempt == RETRIES:
                raise CollectionError('network retry budget exhausted') from None
            sleep(2 ** attempt)
            continue
        if response.status_code == 429 or 500 <= response.status_code < 600:
            if attempt == RETRIES:
                raise CollectionError('HTTP retry budget exhausted')
            sleep(retry_delay(response, attempt))
            continue
        if response.status_code != 200:
            # Never log response payloads, URLs containing tokens, or credentials.
            raise CollectionError('HTTP ' + str(response.status_code))
        try:
            payload = response.json()
        except ValueError:
            raise CollectionError('invalid JSON response') from None
        if not isinstance(payload, dict):
            raise CollectionError('response must be an object')
        return payload
    raise CollectionError('unreachable retry state')


def get_token():
    tenant = os.environ['ENTRA_TENANT_ID']
    payload = request_json(requests.post,
        f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
        data={'client_id': os.environ['ENTRA_CLIENT_ID'],
              'client_secret': os.environ['ENTRA_CLIENT_SECRET'],
              'grant_type': 'client_credentials',
              'scope': 'https://graph.microsoft.com/.default'})
    token = payload.get('access_token')
    if not isinstance(token, str) or not token:
        raise CollectionError('token response missing access_token')
    return token


def valid_next(url):
    if not isinstance(url, str):
        raise CollectionError('invalid nextLink type')
    parts = urlsplit(url)
    expected = urlsplit(AUDIT_URL)
    if (parts.scheme, parts.netloc, parts.path) != (expected.scheme, expected.netloc, expected.path) or parts.fragment:
        raise CollectionError('unexpected pagination destination')
    return url


def fetch_events(token, start, end, get=requests.get, sleep=time.sleep):
    url = AUDIT_URL
    params = {'$filter': f'activityDateTime ge {iso(start)} and activityDateTime le {iso(end)}', '$top': 500}
    visited = set()
    events = {}
    total = 0
    while url:
        if url in visited or len(visited) >= MAX_PAGES:
            raise CollectionError('pagination cycle or page limit')
        visited.add(url)
        body = request_json(get, url, sleep=sleep,
                            headers={'Authorization': f'Bearer {token}'}, params=params)
        rows = body.get('value')
        if not isinstance(rows, list):
            raise CollectionError('missing or invalid value array')
        for event in rows:
            if not isinstance(event, dict) or not isinstance(event.get('id'), str) or not event['id'].strip():
                raise CollectionError('event missing usable ID')
            event_time = timestamp(event.get('activityDateTime'))
            if not start <= event_time <= end:
                raise CollectionError('event outside requested bounds')
            total += 1
            if total > MAX_EVENTS:
                raise CollectionError('event limit exceeded')
            prior = events.get(event['id'])
            if prior is not None and prior != event:
                raise CollectionError('conflicting duplicate event ID')
            events[event['id']] = event
        nxt = body.get('@odata.nextLink')
        url, params = (valid_next(nxt) if nxt else None), None
    return list(events.values()), len(visited)


def atomic_state(path, state):
    fd, temp = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def collect(out, token, *, now=None, get=requests.get, sleep=time.sleep):
    now = now or dt.datetime.now(UTC)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / '.collector.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CollectionError('collector already running') from None
        state_path = out / '.state.json'
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        if not isinstance(state, dict):
            raise CollectionError('invalid checkpoint object')
        checkpoint = timestamp(state['directoryaudits']) if state.get('directoryaudits') else now - dt.timedelta(days=6)
        if checkpoint > now:
            raise CollectionError('checkpoint is in the future')
        start = checkpoint - OVERLAP if state.get('directoryaudits') else checkpoint
        seen = state.get('_directoryaudits_seen', {})
        if not isinstance(seen, dict):
            raise CollectionError('invalid deduplication state')
        seen = {key: value for key, value in seen.items() if timestamp(value) >= start}
        output = out / 'directoryaudits.json'
        # Complete output records are recovery evidence if state replacement failed.
        # Never discard or silently repair malformed/partial existing output.
        if output.exists():
            with output.open() as handle:
                for line in handle:
                    if not line.endswith("\n"):
                        raise CollectionError("unterminated existing output; preserve and repair privately")
                    try:
                        event = json.loads(line)
                        ident = event['id']
                        value = event['activityDateTime']
                        if not isinstance(ident, str) or not ident:
                            raise ValueError()
                        if timestamp(value) >= start:
                            seen[ident] = value
                    except (ValueError, KeyError, TypeError):
                        raise CollectionError('invalid existing output; preserve and repair privately') from None
        events, pages = fetch_events(token, start, now, get, sleep)
        fresh = sorted((e for e in events if e['id'] not in seen), key=lambda e: (timestamp(e['activityDateTime']), e['id']))
        with output.open('a') as handle:
            for event in fresh:
                handle.write(json.dumps(event, separators=(',', ':')) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        latest = max([checkpoint] + [timestamp(e['activityDateTime']) for e in events])
        seen.update({e['id']: e['activityDateTime'] for e in events})
        state['directoryaudits'] = iso(latest)
        state['_directoryaudits_seen'] = {key: value for key, value in seen.items() if timestamp(value) >= latest - OVERLAP}
        state['_collector_version'] = 2
        # Legacy signins checkpoint is retained, but no sign-in request is made.
        atomic_state(state_path, state)
        return {'endpoint': 'directoryaudits', 'pages': pages, 'received': len(events),
                'written': len(fresh), 'duplicates': len(events) - len(fresh),
                'checkpoint': state['directoryaudits'], 'overlap_hours': 24}


def main():
    os.umask(0o077)
    try:
        result = collect(Path(os.environ.get('ENTRA_OUT_DIR', '/var/log/entra')), get_token())
    except Exception as exc:
        message = str(exc) if isinstance(exc, CollectionError) else type(exc).__name__
        print('directoryaudits: FAILED ' + message, file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
