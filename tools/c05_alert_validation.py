"""C05-ALERTS-01 local lab validation helpers. No embedded credentials."""
from pathlib import Path
import csv,io,json,os,re,subprocess,hashlib,time
ROOT=Path('/home/yuji/lab/entra-identity-monitoring-detection')
OUT=ROOT/'docs/evidence/c05-alerts-01'
NAME='ENTRA - App Credential Added Outside Baseline'
LIVE=Path('/opt/splunk/etc/apps/search/local/savedsearches.conf')
SOURCE=ROOT/'detections/savedsearches.conf'
APP='c05_validation_20261016'
APPDIR=Path('/opt/splunk/etc/apps')/APP
BACKUP=Path('/var/backups/c05-alerts-01-20261016')
def command(args,timeout=120):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 return {'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
def query(s):
 r=command(['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','search',s,'-output','csv'])
 r['rows']=list(csv.DictReader(io.StringIO(r['stdout']))) if r['returncode']==0 else []
 return r
def save(n,data):
 p=OUT/n;p.write_text(json.dumps(data,indent=2)+'\n');os.chmod(p,0o600)
 if os.geteuid()==0:
  st=ROOT.stat();os.chown(p,st.st_uid,st.st_gid)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def stanza(t):
 m=re.search(r'(?ms)^\['+re.escape(NAME)+r'\]\n.*?(?=^\[|\Z)',t)
 assert m,'target stanza missing'
 return m
def btool():return command(['/opt/splunk/bin/splunk','btool','savedsearches','list',NAME,'--debug'])
def scheduler():
 return [x for x in Path('/opt/splunk/var/log/splunk/scheduler.log').read_text().splitlines() if NAME in x or APP in x]
