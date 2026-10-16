from c05_d2_capture import *
import os,shutil
a=OUT/'acceptance.json';d=json.loads(a.read_text());assert [k for k,v in d['checks'].items() if not v]==['c09_seven_schedules_healthy']
shutil.copyfile(a,OUT/'acceptance-before-c09-cadence.json')
epoch=json.loads((OUT/'install.json').read_text())['epoch'];deadline=time.time()+360
while time.time()<deadline:
 raw=command(['sudo','-n','cat','/opt/splunk/var/log/splunk/scheduler.log']);assert raw['returncode']==0
 rows=[]
 for line in raw['stdout'].splitlines():
  if 'app="c09_detections"' in line and 'status=' in line:
   r={k:v.strip('"') for k,v in re.findall(r'(?:^|, )([a-z_]+)=("[^"]*"|[^,]*)',line)}
   if float(r.get('scheduled_time','0'))>epoch:rows.append(r)
 assert all(r['status']=='success' for r in rows),'C09 scheduler failure'
 if len({r['savedsearch_name'] for r in rows})==7:
  d['health_scheduler']=[r for r in d['health_scheduler'] if r.get('app')!='c09_detections']+rows
  d['checks']['c09_seven_schedules_healthy']=True;d['all_passed']=all(d['checks'].values());d['health_completion_epoch']=time.time();save('acceptance.json',d)
  print('ALL',len(d['checks']),'ACCEPTANCE CHECKS PASSED',flush=True);break
 time.sleep(10)
else:raise RuntimeError('C09 D3a next normal cadence was not observed')
