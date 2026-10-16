from pathlib import Path
import csv,io,json,subprocess,hashlib,time,copy
ROOT=Path('/home/yuji/lab/entra-identity-monitoring-detection'); OUT=ROOT/'docs/evidence/c05-detect-02'
LOOKUP='c05d2_fixture_baseline.csv'
def query(s):
 a=['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','search',s,'-output','csv','-maxout','0'];p=subprocess.run(a,text=True,capture_output=True,timeout=120)
 return {'command':a,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'rows':list(csv.DictReader(io.StringIO(p.stdout))) if p.returncode==0 else []}
def save(n,d): (OUT/n).write_text(json.dumps(d,indent=2)+'\n')
def event(name,delegated=False,permission=None):
 props=[{'displayName':'ServicePrincipal.ObjectID','newValue':'"fixture-client"'}]
 if delegated:props += [{'displayName':'DelegatedPermissionGrant.Scope','newValue':json.dumps(permission or 'User.Read')},{'displayName':'DelegatedPermissionGrant.ConsentType','newValue':'"AllPrincipals"'}]
 else: props += [{'displayName':'AppRole.Id','newValue':'"fixture-role"'},{'displayName':'AppRole.Value','newValue':json.dumps(permission or 'AuditLog.Read.All')}]
 return {'id':name,'result':'success','activityDisplayName':'Add delegated permission grant' if delegated else 'Add app role assignment to service principal','correlationId':'shared-correlation','initiatedBy':{'user':{'userPrincipalName':'analyst@example.invalid'}},'targetResources':[{'id':'fixture-resource','displayName':'Fixture API','modifiedProperties':props},{'id':'secondary','displayName':'Secondary context','modifiedProperties':[]}]}
def prop(e,n,v):
 for p in e['targetResources'][0]['modifiedProperties']:
  if p['displayName']==n:p['newValue']=v
 return e
def run():
 baseline='client_sp_id,resource_sp_id,grant_type,permission,consent_type\nfixture-client,fixture-resource,application,AuditLog.Read.All,not_applicable\nfixture-client,fixture-resource,application,Directory.Read.All,not_applicable\nfixture-client,fixture-resource,delegated,User.Read,AllPrincipals\n'
 bp=OUT/LOOKUP;bp.write_text(baseline)
 subprocess.run(['sudo','-n','install','-o','splunk','-g','splunk','-m','640',str(bp),'/opt/splunk/etc/apps/search/lookups/'+LOOKUP],check=True)
 s=(ROOT/'detections/c05_permission_grants.preview.spl').read_text();tail=s[s.index('| eval operation='):].replace('lookup entra_approved_grants.csv','lookup '+LOOKUP)
 cases=[]
 def add(n,events,expected):cases.append({'name':n,'events':events,'expected':sorted(expected)})
 ok=lambda p:('approved','none',p)
 bad=lambda p:('outside_baseline','none',p)
 err=lambda why,p:('parse_error',why,p)
 add('approved_application',[event('a')],[ok('AuditLog.Read.All')])
 add('approved_directory',[event('b',permission='Directory.Read.All')],[ok('Directory.Read.All')])
 add('approved_delegated',[event('c',True)],[ok('User.Read')])
 add('new_client',[prop(event('d'),'ServicePrincipal.ObjectID','"other-client"')],[bad('AuditLog.Read.All')])
 e=event('e');e['targetResources'][0]['id']='other-resource';add('new_resource',[e],[bad('AuditLog.Read.All')])
 add('new_permission',[event('f',permission='Mail.Read')],[bad('Mail.Read')])
 add('wrong_grant_type',[event('g',True,'AuditLog.Read.All')],[bad('AuditLog.Read.All')])
 add('wrong_consent',[prop(event('h',True),'DelegatedPermissionGrant.ConsentType','"Principal"')],[bad('User.Read')])
 add('mixed_scopes',[event('i',True,'User.Read   Mail.Read')],[ok('User.Read'),bad('Mail.Read')])
 add('same_correlation',[event('j'),event('k',True,'Mail.Read')],[ok('AuditLog.Read.All'),bad('Mail.Read')])
 for val,label in [('null','literal_null'),('', 'empty'),('   ','spaces')]:
  add(label+'_client',[prop(event(label),'ServicePrincipal.ObjectID',val)],[err('missing_or_ambiguous_attribution','AuditLog.Read.All')])
  e=event(label+'resource');e['targetResources'][0]['id']=val;add(label+'_resource',[e],[err('missing_or_ambiguous_attribution','AuditLog.Read.All')])
 add('missing_app_permission',[prop(event('l'),'AppRole.Value','null')],[err('missing_permission','__missing__')])
 add('missing_scope',[prop(event('m',True),'DelegatedPermissionGrant.Scope','null')],[err('missing_permission','__missing__')])
 add('missing_consent',[prop(event('n',True),'DelegatedPermissionGrant.ConsentType','null')],[err('missing_consent_type','User.Read')])
 e=event('o',True);e['targetResources'][0]['modifiedProperties'].append({'displayName':'DelegatedPermissionGrant.ConsentType','newValue':'"Principal"'});add('conflicting_consent',[e],[err('ambiguous_consent_type','User.Read')])
 e=event('p');e.pop('id');add('missing_id',[e],[err('missing_event_id','AuditLog.Read.All')])
 e=event('q');e['targetResources']=[];add('empty_targets',[e],[err('missing_grant_properties','__missing__')])
 e=event('r');e.pop('targetResources');add('missing_targets',[e],[err('missing_grant_properties','__missing__')])
 e=event('s');e['targetResources']=[{'id':'fixture-resource','modifiedProperties':[]}];add('missing_properties',[e],[err('missing_grant_properties','__missing__')])
 e=event('t');e['result']='failure';add('failed_operation',[e],[])
 e=event('u');e['activityDisplayName']='Consent to application';add('context_only',[e],[])
 e=event('v');e['activityDisplayName']+=' ';add('trailing_operation_space',[e],[ok('AuditLog.Read.All')])
 e=event('w');e['initiatedBy']={'user':{'userPrincipalName':'null'},'app':{'displayName':'Fixture automation'}};add('app_actor',[e],[ok('AuditLog.Read.All')])
 add('empty_results',[],[])
 for c in cases:
  n=len(c['events']);q='| makeresults count='+str(max(n,1))+' | streamstats count AS fixture_number '
  if n:q+='| eval _raw=case('+','.join('fixture_number='+str(i+1)+','+json.dumps(json.dumps(e,separators=(',',':'))) for i,e in enumerate(c['events']))+') | spath | search result=success '
  else:q+='| where 1=0 '
  q+=tail;c['execution']=query(q)
  c['actual']=sorted((r.get('baseline_status',''),r.get('parse_issue',''),r.get('permission','')) for r in c['execution']['rows'])
  c['passed']=c['execution']['returncode']==0 and c['actual']==c['expected'] and all(len(r.get('alert_key',''))==64 for r in c['execution']['rows'])
  if c['name']=='app_actor':c['passed']=c['passed'] and c['execution']['rows'][0].get('actor')=='Fixture automation'
  print(c['name'],c['passed'],c['actual'],flush=True);save('pipeline.json',{'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'cases':cases,'all_passed':all(x.get('passed',False) for x in cases)})
 print('TOTAL',sum(c['passed'] for c in cases),'/',len(cases),flush=True)
 assert all(c['passed'] for c in cases),'Required fixture failed; do not deploy'
if __name__=='__main__':run()
