from c05_alert_validation import *
from urllib.parse import quote
def fields(line):
 return {k:v.strip('"') for k,v in re.findall(r'(?:^|, )([a-z_]+)=("[^"]*"|[^,]*)',line)}
before=json.loads((OUT/'before.json').read_text())
install=json.loads((OUT/'install.json').read_text())
policy=json.loads((OUT/'policy-confirmed-B.json').read_text())
pipe=json.loads((OUT/'pipeline.json').read_text())
rows=[fields(x) for x in policy['scheduler'] if APP in x]
checks={}
for suite in ['empty','sequence','multi']:
 rs=[r for r in rows if r.get('savedsearch_name')=='C05V_'+suite]
 assert rs and all(r['status']=='success' for r in rs)
 alert=policy['alerts'][suite];assert alert['returncode']==0
 sids={r['sid'] for r in alert['rows']}
 firing=[r for r in rs if int(r.get('fired',0))>0]
 checks[suite+'_sid_match']={r['sid'] for r in firing}==sids
 checks[suite+'_outbound_off']=all(r['alert_actions']=='' for r in rs) and all(r['actions']=='' for r in alert['rows'])
 if suite=='empty':checks['empty_silent']=not sids and all(r['result_count']=='0' and r['fired']=='0' for r in rs)
 if suite=='sequence':
  checks['first_id_fires']=any(r['result_count']=='1' and r['fired']=='1' and r['suppressed']=='0' for r in rs)
  checks['repeat_id_suppressed']=any(r['result_count']=='1' and r['fired']=='0' and r['suppressed']=='1' for r in rs)
  checks['different_id_fires']=any(r['result_count']=='2' and r['fired']=='1' and r['suppressed']=='1' for r in rs)
 if suite=='multi':checks['two_distinct_results_fire']=any(r['result_count']=='2' and r['fired']=='2' for r in rs)
checks['stable_policy_during_sequence']=policy['test_conf_sha256']==json.loads((OUT/'policy-repeated-A.json').read_text())['test_conf_sha256']==json.loads((OUT/'policy-new-id-change.json').read_text())['test_conf_sha256']
checks['pipeline_all_passed']=pipe['all_passed']
old=(BACKUP/'savedsearches.conf').read_text();new=LIVE.read_text();a=stanza(old);b=stanza(new)
checks['unrelated_stanzas_unchanged']=old[:a.start()]+old[a.end():]==new[:b.start()]+new[b.end():]
lookup=Path('/opt/splunk/etc/apps/search/lookups/entra_known_apps.csv')
checks['lookup_unchanged']=before['lookup_sha256'] is not None and sha(lookup)==before['lookup_sha256']
checks['metadata_unchanged']=all(Path(p).exists() and sha(p)==v for p,v in before['metadata_sha256'].items())
base=command(['sudo','-n','-u','yuji','git','-C',str(ROOT),'show','9e7d5e1d7c5bf3598984b8d69b58ea23e548a4ee:detections/savedsearches.conf'])['stdout']
checks['source_spl_byte_identical']=base.split('search = ',1)[1]==SOURCE.read_text().split('search = ',1)[1]
current=btool();text=current['stdout']
expected={'counttype':'number of events','relation':'greater than','quantity':'0','alert.digest_mode':'0','alert.track':'1','alert.suppress':'1','alert.suppress.fields':'correlationId','alert.suppress.period':'24h','enableSched':'1','cron_schedule':'*/15 * * * *','dispatch.earliest_time':'-24h','dispatch.latest_time':'now','action.email':'0','action.script':'0','action.webhook':'0'}
checks['effective_values']=all(re.search(r'\s'+re.escape(k)+r' = '+re.escape(v)+r'\s*$',text,re.M) for k,v in expected.items())
checks['invalid_keys_absent']=not any(re.search(r'\s'+k+' =',text) for k in ['alert_type','alert_comparator','alert_threshold'])
config=command(['/opt/splunk/bin/splunk','btool','check']);checks['config_check_clean']=config['returncode']==0 and not config['stdout'] and not config['stderr']
all_lines=Path('/opt/splunk/var/log/splunk/scheduler.log').read_text().splitlines()
live=[fields(x) for x in all_lines if NAME in x and 'status=' in x]
live=[r for r in live if int(r['scheduled_time'])>install['epoch'] and r.get('digest_mode')=='0']
checks['live_normal_schedule_success']=bool(live) and all(r['status']=='success' for r in live)
live_alerts=query('| rest /servicesNS/-/search/alerts/fired_alerts/'+quote(NAME,safe='')+' | table title sid trigger_time actions')
new_alerts=[r for r in live_alerts['rows'] if float(r['trigger_time'])>install['epoch']]
checks['live_results_reconciled']=bool(live) and live_alerts['returncode']==0 and all(r['result_count']=='0' and r.get('fired')=='0' for r in live) and not new_alerts
c09=[fields(x) for x in all_lines if 'app="c09_detections"' in x and 'status=' in x]
c09=[r for r in c09 if int(r['scheduled_time'])>install['epoch']]
checks['c09_scheduler_recovered']=len({r['savedsearch_name'] for r in c09 if r['status']=='success'})==7 and all(r['status']=='success' for r in c09)
service=command(['systemctl','show','Splunkd','-p','ActiveState','-p','SubState','-p','ActiveEnterTimestamp'])
web=command(['curl','--max-time','10','-s','-o','/dev/null','-w','%{http_code}','http://localhost:8000/en-US/account/login'])
checks['service_healthy']='ActiveState=active' in service['stdout'] and 'SubState=running' in service['stdout'] and web['stdout']=='200'
cleanup=query('| rest /servicesNS/-/'+APP+'/saved/searches | search title="C05V_*" | table title is_scheduled')
checks['temporary_schedules_disabled']=len(cleanup['rows'])==3 and all(r['is_scheduled']=='0' for r in cleanup['rows'])
aggregate=query('index=entra_id earliest=0 | stats count max(_time) as latest_event max(_indextime) as latest_index')
save('acceptance.json',{'epoch':time.time(),'checks':checks,'all_passed':all(checks.values()),'policy_scheduler':rows,'live_scheduler':live,'live_alerts':live_alerts,'c09_scheduler':c09,'service':service,'web':web,'btool':current,'config_check':config,'cleanup':cleanup,'retained_telemetry_aggregate':aggregate})
for k,v in checks.items():print(k,v)
assert all(checks.values()),'required acceptance check failed'
