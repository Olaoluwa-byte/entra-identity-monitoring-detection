from pathlib import Path
import subprocess,json,hashlib,time,csv,io,urllib.request
e=Path('/home/yuji/lab/c05-audit-collector/docs/evidence/c05-collect-01');before=json.loads((e/'before.json').read_text());live=Path('/home/yuji/lab/entra-identity-monitoring-detection')
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=45);return {'command':args,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
def search(q):
 r=run(['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','search',q,'-output','csv','-maxout','0']);r['rows']=list(csv.DictReader(io.StringIO(r['stdout'])));return r
result={'epoch':time.time()}
result['invariants']=json.loads(subprocess.check_output(['sudo','-n','python3','-c','import pathlib,hashlib,json; b=json.loads(pathlib.Path('+repr(str(e/'before.json'))+').read_text()); print(json.dumps({p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in b["config_hashes"].items()}))'],text=True))
result['unit_invariants']={key:hashlib.sha256(Path(p).read_bytes()).hexdigest()==before[key] for key,p in [('service_unit_sha256','/etc/systemd/system/entra-pull.service'),('timer_unit_sha256','/etc/systemd/system/entra-pull.timer')]}
result['output']=json.loads(subprocess.check_output(['sudo','-n','python3','-c','import pathlib,hashlib,json; p=pathlib.Path("/var/log/entra/directoryaudits.json"); s=json.loads(pathlib.Path("/var/log/entra/.state.json").read_text()); print(json.dumps({"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"checkpoint":s.get("directoryaudits"),"version":s.get("_collector_version"),"seen_count":len(s.get("_directoryaudits_seen",{}))}))'],text=True))
result['splunk_service']=run(['systemctl','is-active','Splunkd'])
result['collector_service']=run(['systemctl','--no-pager','show','entra-pull.service','-p','Result','-p','ExecMainStatus'])
result['timer']=run(['systemctl','--no-pager','show','entra-pull.timer','-p','ActiveState','-p','UnitFileState'])
result['web_status']=urllib.request.urlopen('http://127.0.0.1:8000',timeout=10).status
result['scheduler']=search('index=_internal sourcetype=scheduler earliest=-30m (savedsearch_name="ENTRA - *" OR app=c09_detections) | stats latest(status) AS latest_status latest(_time) AS latest_run count AS runs BY savedsearch_name | sort savedsearch_name')
result['ingestion']=search('index=entra_id earliest=0 | stats count latest(_time) AS latest_event latest(_indextime) AS latest_index BY sourcetype')
result['config_check']=run(['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','btool','check'])
result['source_live_match']=hashlib.sha256((live/'entra_pull.py').read_bytes()).hexdigest()==hashlib.sha256((e.parents[2]/'entra_pull.py').read_bytes()).hexdigest()
(e/'health.json').write_text(json.dumps(result,indent=2)+chr(10))
print(json.dumps({'invariants':all(result['invariants'].values()),'unit_invariants':all(result['unit_invariants'].values()),'output_unchanged':result['output']['sha256']==before['output_sha256'],'source_live_match':result['source_live_match'],'web':result['web_status'],'scheduler':result['scheduler']['rows'],'scheduler_rc':result['scheduler']['returncode'],'ingestion':result['ingestion']['rows'],'config_check_rc':result['config_check']['returncode']},indent=2))
