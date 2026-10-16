from c05_d2_capture import *
def wait_for(predicate,label,seconds=210):
 deadline=time.time()+seconds
 while time.time()<deadline:
  rows=records()
  assert all(r.get('status')=='success' for r in rows), 'scheduler failure'
  if predicate(rows):print(label,'observed',flush=True);return rows
  time.sleep(10)
 raise RuntimeError('Timed out: '+label)
def seq(rows):return [r for r in rows if r.get('savedsearch_name')=='C05D2_sequence']
wait_for(lambda rows:any(r.get('fired')=='1' for r in seq(rows)) and any(r.get('fired')=='0' and r.get('suppressed')=='1' for r in seq(rows)), 'first firing and repeat suppression')
a=capture('repeat-A');assert all(v['returncode']==0 for v in a['alerts'].values())
p=Path('/opt/splunk/etc/apps/search/lookups/c05d2_policy.csv')
r=command(['sudo','-n','cat',str(p)]);assert r['returncode']==0
rows=list(csv.DictReader(io.StringIO(r['stdout'])));assert not any('sched-B' in x['_raw'] for x in rows)
rows.append({'suite':'sequence','_raw':json.dumps(event('sched-B',permission='Mail.Read'))})
local=OUT/'policy-after-B.csv'
with local.open('w') as f:w=csv.DictWriter(f,fieldnames=['suite','_raw']);w.writeheader();w.writerows(rows)
r=command(['sudo','-n','install','-o','splunk','-g','splunk','-m','640',str(local),str(p)]);assert r['returncode']==0
save('policy-data-change.json',{'epoch':time.time(),'command':r,'config_sha_before':a['live_config_sha'],'config_sha_after':command(['sudo','-n','sha256sum','/opt/splunk/etc/apps/search/local/savedsearches.conf'])})
wait_for(lambda rows:any(r.get('result_count')=='2' and r.get('fired')=='1' and r.get('suppressed')=='1' for r in seq(rows)),'new event key fires while old key stays suppressed')
capture('new-B')
print('SCHEDULED_SEQUENCE_COMPLETE',flush=True)
