from c05_d2_validate import *
import re,sys
from urllib.parse import quote
NAME='ENTRA - Permission Grant Outside Baseline'
def command(a):
 p=subprocess.run(a,text=True,capture_output=True,timeout=120);return dict(command=a,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
def records():
 r=command(['sudo','-n','cat','/opt/splunk/var/log/splunk/scheduler.log']);assert r['returncode']==0
 lines=[x for x in r['stdout'].splitlines() if ('C05D2_' in x or NAME in x) and 'status=' in x]
 return [{'line':x,**{k:v.strip('"') for k,v in re.findall(r'(?:^|, )([a-z_]+)=("[^"]*"|[^,]*)',x)}} for x in lines]
def capture(stage):
 d={'epoch':time.time(),'scheduler':records(),'alerts':{},'effective':query('| rest /servicesNS/-/search/saved/searches | search title="C05D2_*" OR title="'+NAME+'" | table title is_scheduled cron_schedule alert_type alert_comparator alert_threshold alert.digest_mode alert.suppress alert.suppress.fields alert.suppress.period action.email action.script action.webhook search')}
 for name in [NAME,'C05D2_negative','C05D2_sequence','C05D2_multi','C05D2_malformed']:
  d['alerts'][name]=query('| rest /servicesNS/-/search/alerts/fired_alerts/'+quote(name,safe='')+' | table title sid trigger_time actions')
 d['live_config_sha']=command(['sudo','-n','sha256sum','/opt/splunk/etc/apps/search/local/savedsearches.conf'])
 save('runtime-'+stage+'.json',d)
 print('EFFECTIVE',[(r['title'],r.get('is_scheduled')) for r in d['effective']['rows']],flush=True)
 for r in d['scheduler'][-16:]:print(r.get('savedsearch_name'),r.get('scheduled_time'),r.get('status'),r.get('result_count'),r.get('fired'),r.get('suppressed'),flush=True)
 print('ALERT_COUNTS',{k:len(v['rows']) for k,v in d['alerts'].items()},flush=True)
 return d
if __name__=='__main__':capture(sys.argv[1])
