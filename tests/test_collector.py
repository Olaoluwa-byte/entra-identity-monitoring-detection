import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import requests

spec = importlib.util.spec_from_file_location('collector', Path(__file__).resolve().parents[1] / 'entra_pull.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
NOW = dt.datetime(2026, 10, 16, 19, 0, tzinfo=dt.timezone.utc)
T = '2026-10-16T18:00:00Z'

def event(ident='a', stamp=T):
    return {'id': ident, 'activityDateTime': stamp, 'activityDisplayName': 'fixture'}

class Response:
    def __init__(self, data=None, status=200, headers=None):
        self.data = data
        self.status_code = status
        self.headers = headers or {}
    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data

class Queue:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
    def run_collect(self, *responses):
        q = Queue(*responses)
        return c.collect(self.out, 'fixture-token', now=NOW, get=q, sleep=lambda _: None), q
    def rows(self):
        p = self.out / 'directoryaudits.json'
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
    def test_audit_only_and_repeat_dedup(self):
        r,q = self.run_collect(Response({'value':[event()]}))
        self.assertEqual(r['written'],1)
        self.assertEqual(q.calls[0][0],c.AUDIT_URL)
        self.assertFalse(q.calls[0][1]['allow_redirects'])
        r,q = self.run_collect(Response({'value':[event()]}))
        self.assertEqual(r['written'],0)
        self.assertEqual(len(self.rows()),1)
    def test_equal_timestamps_distinct_ids(self):
        self.run_collect(Response({'value':[event('a')]}))
        self.run_collect(Response({'value':[event('a'),event('b')]}))
        self.assertEqual(len(self.rows()),2)
    def test_late_record_and_overlap(self):
        self.run_collect(Response({'value':[event()]}))
        r,q=self.run_collect(Response({'value':[event('late','2026-10-15T19:00:00Z')]}))
        self.assertEqual(r['written'],1)
        self.assertIn('ge 2026-10-15T18:00:00Z',q.calls[0][1]['params']['$filter'])
    def test_paginate_and_page_duplicate(self):
        r,q=self.run_collect(Response({'value':[event()], '@odata.nextLink':c.AUDIT_URL+'?$skiptoken=fixture'}),Response({'value':[event(),event('b')]}))
        self.assertEqual((r['pages'],r['written']),(2,2))
        self.assertIsNone(q.calls[1][1]['params'])
    def test_later_page_failure_no_output_or_state(self):
        with self.assertRaises(c.CollectionError):
            self.run_collect(Response({'value':[event()], '@odata.nextLink':c.AUDIT_URL+'?page=2'}),Response({},403))
        self.assertEqual(self.rows(),[])
        self.assertFalse((self.out/'.state.json').exists())
    def test_bad_nextlink_no_credential_forward(self):
        q=Queue(Response({'value':[], '@odata.nextLink':'https://example.invalid/steal'}))
        with self.assertRaises(c.CollectionError):
            c.collect(self.out,'fixture',now=NOW,get=q)
        self.assertEqual(len(q.calls),1)
    def test_pagination_cycle(self):
        with self.assertRaises(c.CollectionError):
            self.run_collect(Response({'value':[], '@odata.nextLink':c.AUDIT_URL}))
    def test_429_retry_after(self):
        delays=[];q=Queue(Response({},429,{'Retry-After':'3'}),Response({'value':[]}))
        c.collect(self.out,'fixture',now=NOW,get=q,sleep=delays.append)
        self.assertEqual(delays,[3])
    def test_transient_network_and_503(self):
        r,q=self.run_collect(requests.Timeout(),Response({},503),Response({'value':[event()]}))
        self.assertEqual((r['written'],len(q.calls)),(1,3))
    def test_retry_exhaustion(self):
        with self.assertRaises(c.CollectionError):
            self.run_collect(*[Response({},503) for _ in range(5)])
    def test_long_retry_not_shortened(self):
        with self.assertRaises(c.CollectionError):
            self.run_collect(Response({},429,{'Retry-After':'301'}))
    def test_http_failures_do_not_advance(self):
        self.run_collect(Response({'value':[event()]})); before=(self.out/'.state.json').read_bytes()
        for status in (401,403,302,400):
            with self.subTest(status=status),self.assertRaises(c.CollectionError):
                self.run_collect(Response({},status))
            self.assertEqual((self.out/'.state.json').read_bytes(),before)
    def test_invalid_response(self):
        for data in ({}, {'value':None}, [], ValueError('payload')):
            with self.subTest(data=str(data)),self.assertRaises(c.CollectionError):
                self.run_collect(Response(data))
    def test_invalid_event(self):
        for row in ({},event('',T),event('a','bad'),event('a','2026-10-16T18:00:00'),event('a','2026-10-17T18:00:00Z')):
            with self.subTest(row=row),self.assertRaises(c.CollectionError):
                self.run_collect(Response({'value':[row]}))
    def test_conflicting_duplicate(self):
        with self.assertRaises(c.CollectionError):
            self.run_collect(Response({'value':[event(),event('a','2026-10-16T18:01:00Z')]}))
    def test_empty_and_legacy_state_preserved(self):
        (self.out/'.state.json').write_text(json.dumps({'directoryaudits':T,'signins':'legacy'}))
        r,q=self.run_collect(Response({'value':[]}))
        state=json.loads((self.out/'.state.json').read_text())
        self.assertEqual(state['signins'],'legacy');self.assertEqual(r['written'],0)
        self.assertEqual(c.timestamp(state['directoryaudits']),c.timestamp(T))
    def test_output_before_checkpoint_recovered(self):
        with patch.object(c,'atomic_state',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                self.run_collect(Response({'value':[event()]}))
        self.assertEqual(len(self.rows()),1)
        r,q=self.run_collect(Response({'value':[event()]}))
        self.assertEqual(r['written'],0);self.assertEqual(len(self.rows()),1)
    def test_atomic_replace_failure_preserves_old_state(self):
        p=self.out/'.state.json';p.write_text('{"old":true}')
        with patch.object(c.os,'replace',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):c.atomic_state(p,{'new':True})
        self.assertEqual(json.loads(p.read_text()),{'old':True})
        self.assertEqual(list(self.out.glob('.state-*')),[])
    def test_partial_existing_output_fails_closed(self):
        p=self.out/'directoryaudits.json';p.write_text('{"id":')
        with self.assertRaises(c.CollectionError):self.run_collect(Response({'value':[]}))
        self.assertEqual(p.read_text(),'{"id":')
    def test_complete_unterminated_output_fails_closed(self):
        p=self.out/'directoryaudits.json';p.write_text(json.dumps(event()))
        with self.assertRaises(c.CollectionError):self.run_collect(Response({'value':[]}))
    def test_lock_excludes_overlap(self):
        with (self.out/'.collector.lock').open('a') as lock:
            c.fcntl.flock(lock,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB)
            with self.assertRaises(c.CollectionError):self.run_collect(Response({'value':[]}))
    def test_future_checkpoint_fails_closed(self):
        (self.out/'.state.json').write_text(json.dumps({'directoryaudits':'2027-01-01T00:00:00Z'}))
        with self.assertRaises(c.CollectionError):self.run_collect(Response({'value':[]}))
    def test_main_nonzero_and_sanitized(self):
        with patch.object(c,'get_token',side_effect=RuntimeError('secret payload')),patch('sys.stderr') as err:
            self.assertEqual(c.main(),1)
            self.assertNotIn('secret payload',str(err.write.call_args_list))

if __name__=='__main__':unittest.main(verbosity=2)
