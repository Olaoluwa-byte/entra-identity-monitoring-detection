from c05_d2_validate import *
import os,shutil,re
NAME='ENTRA - Permission Grant Outside Baseline'
LIVE=Path('/opt/splunk/etc/apps/search/local/savedsearches.conf')
BACK=Path('/var/backups/c05-detect-02-20261016')
def command(a):
 p=subprocess.run(a,capture_output=True,text=True,timeout=120);return dict(command=a,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
def install():
 assert os.geteuid()==0
 assert json.loads((OUT/'pipeline.json').read_text())['all_passed']
 before=json.loads((OUT/'before.json').read_text()); hashes={line.split(None,1)[1]:line.split()[0] for line in before['live_hashes']['stdout'].splitlines()}
 for p,h in hashes.items():assert hashlib.sha256(Path(p).read_bytes()).hexdigest()==h,('drift',p)
 old=LIVE.read_text();assert NAME not in old and '[C05D2_' not in old
 shutil.copy2(LIVE,BACK/'pre-d2-savedsearches.conf');os.chmod(BACK/'pre-d2-savedsearches.conf',0o600)
 src=ROOT/'detections/savedsearches.conf';(OUT/'source-before.conf').write_text(src.read_text())
 policy='enableSched = 1\ncron_schedule = */15 * * * *\ndispatch.earliest_time = -24h\ndispatch.latest_time = now\ncounttype = number of events\nrelation = greater than\nquantity = 0\nalert.track = 1\nalert.digest_mode = 0\nalert.suppress = 1\nalert.suppress.fields = alert_key\nalert.suppress.period = 24h\nalert.severity = 3\naction.email = 0\naction.script = 0\naction.webhook = 0\n'
 spl=(ROOT/'detections/c05_permission_grants.spl').read_text()
 stanza='['+NAME+']\n'+policy+'description = Successful permission grants outside the approved five-field baseline, including explicit parse errors.\nsearch = '+ ' '.join(spl.splitlines())+'\n'
 src.write_text(src.read_text()+'\n'+stanza)
 tail=spl[spl.index('| eval operation='):].replace('lookup entra_approved_grants.csv','lookup '+LOOKUP)
 testconf='';names=[]
 for suite in ['negative','sequence','multi','malformed']:
  name='C05D2_'+suite;names.append(name)
  q='| inputlookup c05d2_policy.csv | where suite="'+suite+'" | spath | search result=success '+tail
  testconf+='\n['+name+']\n'+policy.replace('*/15 * * * *','* * * * *')+'search = '+' '.join(q.splitlines())+'\n'
 fixture=[{'suite':'negative','_raw':json.dumps(event('sched-approved'))},{'suite':'sequence','_raw':json.dumps(event('sched-A',permission='Mail.Read'))},{'suite':'multi','_raw':json.dumps(event('sched-M1',True,'Mail.Read Files.Read'))},{'suite':'malformed','_raw':json.dumps(prop(event('sched-bad'),'ServicePrincipal.ObjectID','null'))}]
 fp=Path('/opt/splunk/etc/apps/search/lookups/c05d2_policy.csv');assert not fp.exists()
 with fp.open('w') as f:w=csv.DictWriter(f,fieldnames=['suite','_raw']);w.writeheader();w.writerows(fixture)
 shutil.chown(fp,user='splunk',group='splunk');os.chmod(fp,0o640)
 LIVE.write_text(old+'\n'+stanza+testconf)
 d={'epoch':time.time(),'live_name':NAME,'test_names':names,'test_config':testconf,'live_stanza':stanza,'fixture':fixture,'unrelated_prefix_unchanged':LIVE.read_text().startswith(old),'btool':command(['/opt/splunk/bin/splunk','btool','savedsearches','list',NAME,'--debug']),'config_check':command(['/opt/splunk/bin/splunk','btool','check'])}
 save('install.json',d)
 st=ROOT.stat()
 for p in [src,*OUT.iterdir()]:os.chown(p,st.st_uid,st.st_gid)
 assert d['config_check']['returncode']==0,d['config_check']
 print('INSTALLED_D2_AND_ISOLATED_TEST_STANZAS',flush=True)
 r=command(['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','_internal','call','/servicesNS/nobody/search/saved/searches/_reload','-method','POST']);save('reload.json',r);os.chown(OUT/'reload.json',st.st_uid,st.st_gid);print(r,flush=True)
if __name__=='__main__':install()
