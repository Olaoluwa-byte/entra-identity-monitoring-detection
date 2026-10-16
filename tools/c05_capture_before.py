from c05_alert_validation import *
import tarfile
assert sha(SOURCE)=='21d4580d3a83cc49f438ad1bb758d81cb46b0df54b0b6be6c6947fc0415245f4'
assert not BACKUP.exists(),'backup exists: inspect before retry'
BACKUP.mkdir(mode=0o700)
paths=[LIVE,Path('/opt/splunk/etc/apps/search/metadata'),Path('/opt/splunk/etc/apps/search/lookups/entra_known_apps.csv'),Path('/opt/splunk/var/lib/splunk/alert_actions')]
with tarfile.open(BACKUP/'before.tgz','w:gz') as t:
 for p in paths:
  if p.exists():t.add(p,arcname=str(p).lstrip('/'))
os.chmod(BACKUP/'before.tgz',0o600)
(BACKUP/'savedsearches.conf').write_bytes(LIVE.read_bytes());os.chmod(BACKUP/'savedsearches.conf',0o600)
meta={str(p):sha(p) for p in paths[1].rglob('*') if p.is_file()}
save('before.json',{'epoch':time.time(),'source_sha256':sha(SOURCE),'live_sha256':sha(LIVE),'lookup_sha256':sha(paths[2]) if paths[2].exists() else None,'metadata_sha256':meta,'backup':str(BACKUP/'before.tgz'),'backup_sha256':sha(BACKUP/'before.tgz'),'btool':btool(),'scheduler':scheduler()[-8:],'alerts':query('| rest /servicesNS/-/search/alerts/fired_alerts | search title="*ENTRA*" | table title triggered_alert_count')})
print('BACKUP_AND_BEFORE_CAPTURED',str(BACKUP),flush=True)
