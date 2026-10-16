from pathlib import Path
import hashlib,json,subprocess,os
root=Path.cwd(); out=root/'docs/evidence/c05-detect-02'
def cmd(a):
 p=subprocess.run(a,text=True,capture_output=True);return dict(command=a,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert cmd(['git','rev-parse','HEAD'])['stdout'].strip()=='e1f33d34deb9ec9cdba5a71d29ce8405ede5bdca'
assert cmd(['git','branch','--show-current'])['stdout'].strip()=='feat/c05-permission-grants'
if not (out/'before.json').exists():
 d={'git':cmd(['git','status','--short','--branch']),'backup_stat':cmd(['sudo','-n','stat','-c','%a %U %G %s','/var/backups/c05-detect-02-20261016/before.tgz']),'backup_sha':cmd(['sudo','-n','sha256sum','/var/backups/c05-detect-02-20261016/before.tgz']),'backup_members':cmd(['sudo','-n','tar','-tzf','/var/backups/c05-detect-02-20261016/before.tgz']),'live_hashes':cmd(['sudo','-n','sha256sum','/opt/splunk/etc/apps/search/local/savedsearches.conf','/opt/splunk/etc/apps/search/metadata/local.meta','/opt/splunk/etc/apps/search/lookups/entra_known_apps.csv','/opt/splunk/etc/apps/search/lookups/entra_approved_grants.csv'])}
 (out/'before.json').write_text(json.dumps(d,indent=2)+'\n')
 for k in ['backup_stat','backup_sha','backup_members','live_hashes']:assert d[k]['returncode']==0,(k,d[k])
source=root/'detections/c05_permission_grants.preview.spl';s=source.read_text()
assert '| eval actor=' not in s, 'Preparation is one-time; candidate already generated'
(out/'manual-preview.spl').write_text(s)
s=s.replace('| eval missing_id=', '| eval id=trim(id)\n| spath path=initiatedBy.user.userPrincipalName output=actor_user\n| spath path=initiatedBy.app.displayName output=actor_app\n| eval actor=case(isnotnull(actor_user) AND actor_user!="null" AND actor_user!="",actor_user,isnotnull(actor_app) AND actor_app!="null" AND actor_app!="",actor_app,true(),"unknown")\n| eval missing_id=',1)
s=s.replace('| spath input=target path=displayName output=resource_name','| eval resource_sp_id=trim(resource_sp_id)\n| eval resource_sp_id=if(resource_sp_id="" OR lower(resource_sp_id)="null",null(),resource_sp_id)\n| spath input=target path=displayName output=resource_name')
s=s.replace('| eval property_value=if(property_value=', '| eval property_value=trim(property_value)\n| eval property_value=if(property_value=',1)
s=s.replace('    values(operation) AS operation','    values(actor) AS actor\n    values(operation) AS operation',1)
s=s[:s.rindex('| table ')]
s+='| eval key_consent=mvjoin(mvsort(consent_type),";")\n'
s+='| eval alert_key=sha256(len(event_id).":".event_id.len(client_sp_id).":".client_sp_id.len(resource_sp_id).":".resource_sp_id.len(grant_type).":".grant_type.len(permission).":".permission.len(key_consent).":".key_consent.len(parse_issue).":".parse_issue)\n'
table='| table _time event_id correlationId actor client_sp_id resource_sp_id resource_name grant_type permission consent_type parse_issue baseline_status alert_key\n'
source.write_text(s+table)
prod=s.replace('earliest=0','earliest=-24h latest=now _index_earliest=-35m',1)+'| where baseline_status!="approved"\n'+table
(root/'detections/c05_permission_grants.spl').write_text(prod)
print('Prepared preview and production candidate; before evidence captured.')
