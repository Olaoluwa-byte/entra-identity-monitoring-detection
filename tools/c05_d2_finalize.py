from c05_d2_capture import *
import os
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 assert os.geteuid()==0
 ins=json.loads((OUT/'install.json').read_text());before=json.loads((OUT/'before.json').read_text())
 d=capture('final-before-cleanup');checks={}
 rs=d['scheduler'];by=lambda n:[r for r in rs if r.get('savedsearch_name')==n]
 checks['all_scheduler_success']=bool(rs) and all(r.get('status')=='success' for r in rs)
 for suite in ['negative','sequence','multi','malformed']:
  name='C05D2_'+suite;r=by(name);a=d['alerts'][name]
  checks[suite+'_sid_match']=bool(r) and a['returncode']==0 and {x['sid'] for x in r if int(x.get('fired','0'))>0}=={x['sid'] for x in a['rows']}
  checks[suite+'_outbound_off']=all(x.get('alert_actions','')=='' for x in r) and all(x.get('actions','')=='' for x in a['rows'])
 checks['approved_scheduled_silent']=bool(by('C05D2_negative')) and all(r['result_count']=='0' and r['fired']=='0' for r in by('C05D2_negative'))
 seq=by('C05D2_sequence')
 checks['positive_scheduled_fires']=any(r['result_count']=='1' and r['fired']=='1' for r in seq)
 checks['repeat_key_suppressed']=any(r['result_count']=='1' and r['fired']=='0' and r['suppressed']=='1' for r in seq)
 checks['new_key_fires']=any(r['result_count']=='2' and r['fired']=='1' and r['suppressed']=='1' for r in seq)
 checks['two_permissions_fire_separately']=any(r['result_count']=='2' and r['fired']=='2' for r in by('C05D2_multi'))
 checks['malformed_scheduled_fires']=any(r['result_count']=='1' and r['fired']=='1' for r in by('C05D2_malformed'))
 change=json.loads((OUT/'policy-data-change.json').read_text());checks['stable_config_during_suppression']=change['config_sha_before']['stdout']==change['config_sha_after']['stdout']==d['live_config_sha']['stdout']
 live=by(NAME);checks['normal_live_run']=bool(live) and all(r['result_count']=='0' and r['fired']=='0' and r['status']=='success' for r in live) and d['alerts'][NAME]['returncode']==0 and not d['alerts'][NAME]['rows']
 pipe=json.loads((OUT/'pipeline.json').read_text());checks['all_29_parser_fixtures']=pipe['all_passed'] and len(pipe['cases'])==29
 checks['validated_preview_unchanged']=sha(ROOT/'detections/c05_permission_grants.preview.spl')==pipe['source_sha256']
 preview=(ROOT/'detections/c05_permission_grants.preview.spl').read_text();prod=(ROOT/'detections/c05_permission_grants.spl').read_text()
 expected=preview[:preview.rindex('| table ')].replace('earliest=0','earliest=-24h latest=now _index_earliest=-35m',1)+'| where baseline_status!="approved"\n'+preview[preview.rindex('| table '):]
 checks['production_parser_matches_validated_preview']=expected==prod
 path=Path('/opt/splunk/etc/apps/search/local/savedsearches.conf');old=Path('/var/backups/c05-detect-02-20261016/pre-d2-savedsearches.conf').read_text()
 checks['unrelated_live_config_unchanged']=path.read_text()==old+'\n'+ins['live_stanza']+ins['test_config']
 source=(ROOT/'detections/savedsearches.conf').read_text();base=(OUT/'source-before.conf').read_text()
 checks['existing_source_unchanged']=source==base+'\n'+ins['live_stanza']
 checks['baseline_source_live_match']=sha(ROOT/'lookups/entra_approved_grants.csv')==sha('/opt/splunk/etc/apps/search/lookups/entra_approved_grants.csv')
 hashes={line.split(None,1)[1]:line.split()[0] for line in before['live_hashes']['stdout'].splitlines()}
 checks['metadata_and_existing_lookups_unchanged']=all(sha(p)==h for p,h in hashes.items() if p!=str(path))
 historical=query(preview+' | stats count by permission baseline_status parse_issue');save('historical-summary.json',historical)
 checks['historical_three_approved']=historical['returncode']==0 and len(historical['rows'])==3 and all(r['baseline_status']=='approved' and r['parse_issue']=='none' and r['count']=='1' for r in historical['rows'])
 b=command(['/opt/splunk/bin/splunk','btool','savedsearches','list',NAME,'--debug']);save('effective-config.json',b)
 expected_keys={'enableSched':'1','cron_schedule':'*/15 * * * *','dispatch.earliest_time':'-24h','dispatch.latest_time':'now','counttype':'number of events','relation':'greater than','quantity':'0','alert.track':'1','alert.digest_mode':'0','alert.suppress':'1','alert.suppress.fields':'alert_key','alert.suppress.period':'24h','action.email':'0','action.script':'0','action.webhook':'0'}
 checks['effective_config_valid']=b['returncode']==0 and all(re.search(r'\s'+re.escape(k)+r' = '+re.escape(v)+r'\s*$',b['stdout'],re.M) for k,v in expected_keys.items())
 cfg=command(['/opt/splunk/bin/splunk','btool','check']);checks['config_check_clean']=cfg['returncode']==0 and not cfg['stdout'] and not cfg['stderr']
 logs=Path('/opt/splunk/var/log/splunk/scheduler.log').read_text().splitlines();health=[]
 for x in logs:
  if ('app="c09_detections"' in x or 'ENTRA - App Credential Added Outside Baseline' in x) and 'status=' in x:
   r={k:v.strip('"') for k,v in re.findall(r'(?:^|, )([a-z_]+)=("[^"]*"|[^,]*)',x)}
   if float(r.get('scheduled_time','0'))>ins['epoch']:health.append(r)
 checks['d1_scheduler_healthy']=any(r.get('savedsearch_name')=='ENTRA - App Credential Added Outside Baseline' and r.get('status')=='success' for r in health)
 c09=[r for r in health if r.get('app')=='c09_detections'];checks['c09_seven_schedules_healthy']=len({r['savedsearch_name'] for r in c09 if r.get('status')=='success'})==7 and all(r.get('status')=='success' for r in c09)
 service=command(['systemctl','show','Splunkd','-p','ActiveState','-p','SubState']);web=command(['curl','--max-time','10','-s','-o','/dev/null','-w','%{http_code}','http://127.0.0.1:8000/en-US/account/login'])
 checks['service_and_web_healthy']='ActiveState=active' in service['stdout'] and 'SubState=running' in service['stdout'] and web['stdout']=='200'
 # Disable only the four temporary schedules; retain fixtures and alert evidence.
 text=path.read_text()
 for name in ins['test_names']:
  pat=r'(?ms)^\['+re.escape(name)+r'\]\n.*?(?=^\[|\Z)';m=re.search(pat,text);assert m
  stanza=m.group();assert stanza.count('enableSched = 1')==1
  text=text[:m.start()]+stanza.replace('enableSched = 1','enableSched = 0',1)+text[m.end():]
 path.write_text(text)
 reload=command(['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','_internal','call','/servicesNS/nobody/search/saved/searches/_reload','-method','POST'])
 clean=query('| rest /servicesNS/-/search/saved/searches | search title="C05D2_*" OR title="'+NAME+'" | table title is_scheduled')
 checks['temporary_schedules_disabled']=clean['returncode']==0 and len([r for r in clean['rows'] if r['title'].startswith('C05D2_')])==4 and all(r['is_scheduled']=='0' for r in clean['rows'] if r['title'].startswith('C05D2_'))
 checks['live_d2_stays_enabled']=any(r['title']==NAME and r['is_scheduled']=='1' for r in clean['rows'])
 save('acceptance.json',{'epoch':time.time(),'checks':checks,'all_passed':all(checks.values()),'scheduler':rs,'health_scheduler':health,'service':service,'web':web,'config_check':cfg,'cleanup':clean,'cleanup_reload':reload,'limitations':['Synthetic and historical evidence; no fresh tenant grant','24-hour expiry not waited out','Coordinator interrupted only the polling helper after data change; scheduler searches continued unchanged. Final capture verifies outcomes.']})
 st=ROOT.stat()
 for p in OUT.iterdir():os.chown(p,st.st_uid,st.st_gid)
 for k,v in checks.items():print(k,v,flush=True)
 assert all(checks.values()),'Required acceptance check failed'
 print('READY_FOR_INDEPENDENT_REVIEW',flush=True)
if __name__=='__main__':main()
