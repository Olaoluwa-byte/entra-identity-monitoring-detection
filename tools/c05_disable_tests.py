from c05_alert_validation import *
r={'epoch':time.time(),'calls':{}}
for suite in ['empty','sequence','multi']:
 r['calls'][suite]=command(['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','_internal','call','/servicesNS/nobody/'+APP+'/saved/searches/C05V_'+suite,'-method','POST','-post:is_scheduled','0'])
 response=r['calls'][suite].pop('stdout')
 r['calls'][suite]['response_sha256']=hashlib.sha256(response.encode()).hexdigest()
 r['calls'][suite]['http_status']=re.search(r'HTTP Status: (\d+)',response).group(1)
 print(suite,r['calls'][suite]['returncode'],r['calls'][suite]['stderr'][-300:],flush=True)
r['effective']=query('| rest /servicesNS/-/'+APP+'/saved/searches | search title="C05V_*" | table title is_scheduled')
r['conf']=(APPDIR/'local/savedsearches.conf').read_text()
save('cleanup.json',r)
print('EFFECTIVE',r['effective']['rows'])
assert len(r['effective']['rows'])==3 and all(x['is_scheduled']=='0' for x in r['effective']['rows'])
