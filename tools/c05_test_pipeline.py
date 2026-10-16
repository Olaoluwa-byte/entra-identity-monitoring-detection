from c05_alert_validation import *
import shutil
fields=['_time','result','activityDisplayName','initiatedBy.user.userPrincipalName','initiatedBy.app.displayName','targetResources{}.displayName','targetResources{}.id','targetResources{}.modifiedProperties{}.newValue','initiatedBy.user.ipAddress','correlationId']
base=[str(int(time.time())),'success','Update application - Certificates and secrets management ','approved@example.invalid','null','Fixture App','fixture-approved','KeyType=Password','192.0.2.10','']
cases=[]
def add(n,expected,changes):
 row=base.copy();row[-1]=n
 for k,v in changes.items():row[fields.index(k)]=v
 cases.append({'case':n,'expected':expected,'fixture':dict(zip(fields,row))})
add('approved',0,{})
add('unknown_update',1,{'targetResources{}.id':'fixture-unknown'})
add('wrong_actor',1,{'initiatedBy.user.userPrincipalName':'rogue@example.invalid'})
add('unknown_create',1,{'activityDisplayName':'Create application - Certificates and secrets management ','targetResources{}.id':'fixture-unknown','targetResources{}.modifiedProperties{}.newValue':''})
add('app_actor_fallback',1,{'initiatedBy.user.userPrincipalName':'null','initiatedBy.app.displayName':'Fixture Service','targetResources{}.id':'fixture-unknown'})
add('unknown_actor',1,{'initiatedBy.user.userPrincipalName':'null','targetResources{}.id':'fixture-unknown'})
add('failed_operation',0,{'result':'failure','targetResources{}.id':'fixture-unknown'})
add('unrelated_operation',0,{'activityDisplayName':'Delete application','targetResources{}.id':'fixture-unknown'})
p=APPDIR/'lookups/c05_events.csv'
with p.open('w') as f:
 w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(c['fixture'] for c in cases)
shutil.chown(p,user='splunk',group='splunk')
spl=SOURCE.read_text().split('search = ',1)[1].replace('\\\n',' ').strip()
tail=spl[spl.index('| eval'):].replace('lookup entra_known_apps.csv','lookup c05_baseline.csv')
for c in cases:
 q='| inputlookup c05_events.csv | search result=success activityDisplayName="*Certificates and secrets management*" correlationId="'+c['case']+'" '+tail
 c['execution']=query(q);c['actual']=len(c['execution']['rows']);c['passed']=c['execution']['returncode']==0 and c['actual']==c['expected']
 if c['passed'] and c['expected']:
  row=c['execution']['rows'][0]
  if c['case']=='unknown_create':c['passed']=row.get('key_type')=='not logged' and row.get('cred_context')=='added at app creation'
  if c['case']=='unknown_update':c['passed']=row.get('key_type')=='Password'
  if c['case']=='app_actor_fallback':c['passed']=row.get('actor')=='Fixture Service'
  if c['case']=='unknown_actor':c['passed']=row.get('actor')=='unknown'
 print(c['case'],c['actual'],c['passed'],flush=True)
 save('pipeline.json',{'cases':cases,'all_passed':all(x.get('passed',False) for x in cases),'limitations':'Synthetic extracted fields; no fresh Entra ingestion or index-time selector validation.'})
save('post-restart.json',{'epoch':time.time(),'service':command(['systemctl','is-active','Splunkd']),'web':command(['curl','-s','-o','/dev/null','-w','%{http_code}','http://localhost:8000']),'btool':btool(),'effective':query('| rest /servicesNS/-/-/saved/searches | search title="C05V_*" OR title="ENTRA - App Credential Added Outside Baseline" | table title alert_type alert_comparator alert_threshold alert.digest_mode is_scheduled cron_schedule'),'scheduler':scheduler()[-30:]})
assert all(c['passed'] for c in cases),'pipeline case failed'
