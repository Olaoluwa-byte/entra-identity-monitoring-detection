from c05_alert_validation import *
import sys
stage=sys.argv[1]
r={'epoch':time.time(),'stage':stage,'scheduler':scheduler(),'test_conf_sha256':sha(APPDIR/'local/savedsearches.conf'),'fixture':(APPDIR/'lookups/c05_policy.csv').read_text(),'alerts':{}}
for suite in ['empty','sequence','multi']:
 r['alerts'][suite]=query('| rest /servicesNS/-/'+APP+'/alerts/fired_alerts/C05V_'+suite+' | table title sid trigger_time severity actions')
 print(suite,r['alerts'][suite]['returncode'],r['alerts'][suite]['rows'],flush=True)
save('policy-'+stage+'.json',r)
print('RECENT_SCHEDULER')
for x in r['scheduler'][-12:]:print(x)
