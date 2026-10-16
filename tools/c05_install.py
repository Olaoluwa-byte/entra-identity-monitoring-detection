from c05_alert_validation import *
import shutil
before=json.loads((OUT/'before.json').read_text())
assert sha(LIVE)==before['live_sha256'],'live drift'
assert sha(SOURCE)==before['source_sha256'],'source drift'
old=SOURCE.read_text();new=old
for a,b in [('alert_type = number of events','counttype = number of events'),('alert_comparator = greater than','relation = greater than'),('alert_threshold = 0','quantity = 0')]:
 assert new.count(a)==1;new=new.replace(a,b)
new=new.replace('alert.track = 1','alert.track = 1\nalert.digest_mode = 0\naction.email = 0\naction.script = 0\naction.webhook = 0')
assert old.split('search = ',1)[1]==new.split('search = ',1)[1]
text=LIVE.read_text();m=stanza(text);changed=text[:m.start()]+new.rstrip()+'\n\n'+text[m.end():]
assert stanza(text).group().split('search = ',1)[1].strip().replace('\\\n',' ')==stanza(changed).group().split('search = ',1)[1].strip().replace('\\\n',' ')
assert not APPDIR.exists()
for d in ['local','metadata','lookups']:(APPDIR/d).mkdir(parents=True,exist_ok=True)
(APPDIR/'local/app.conf').write_text('[install]\nstate = enabled\n[ui]\nis_visible = 0\n')
(APPDIR/'metadata/local.meta').write_text('[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n')
policy='enableSched = 1\ncron_schedule = * * * * *\ndispatch.earliest_time = -5m\ndispatch.latest_time = now\ncounttype = number of events\nrelation = greater than\nquantity = 0\nalert.track = 1\nalert.digest_mode = 0\nalert.suppress = 1\nalert.suppress.fields = correlationId\nalert.suppress.period = 24h\naction.email = 0\naction.script = 0\naction.webhook = 0\n'
conf=''
for suite in ['empty','sequence','multi']:
 conf+='[C05V_'+suite+']\n'+policy+'search = | inputlookup c05_policy.csv | where suite="'+suite+'" | table correlationId\n\n'
(APPDIR/'local/savedsearches.conf').write_text(conf)
(APPDIR/'lookups/c05_policy.csv').write_text('suite,correlationId\nsequence,c05-A\nmulti,c05-M1\nmulti,c05-M2\n')
(APPDIR/'lookups/c05_baseline.csv').write_text('target_id,approved_actor\nfixture-approved,approved@example.invalid\n')
for p in [APPDIR,*APPDIR.rglob('*')]:shutil.chown(p,user='splunk',group='splunk')
SOURCE.write_text(new);st=ROOT.stat();os.chown(SOURCE,st.st_uid,st.st_gid)
LIVE.write_text(changed)
# Assert unrelated live stanzas are unchanged.
assert text[:m.start()]+text[m.end():]==changed[:stanza(changed).start()]+changed[stanza(changed).end():]
save('install.json',{'epoch':time.time(),'source_spl_byte_identical':True,'unrelated_stanzas_unchanged':True,'btool':btool(),'config_check':command(['/opt/splunk/bin/splunk','btool','check']),'test_conf':conf})
print('INSTALLED_CONFIG_AND_ISOLATED_HARNESS',flush=True)
