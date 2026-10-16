from pathlib import Path
import hashlib,json,subprocess,sys,tarfile
ROOT=Path('/home/yuji/lab/entra-identity-monitoring-detection');OUT=ROOT/'docs/evidence/c05-detect-02'
def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert json.loads((OUT/'acceptance.json').read_text())['all_passed'],'Acceptance incomplete'
if sys.argv[1]=='manifest':
 (OUT/'source.diff').write_text(git('diff','--cached','e1f33d34deb9ec9cdba5a71d29ce8405ede5bdca','--','README.md','detections','lookups/entra_approved_grants.csv','tools','docs/c05-detect-02-validation.md'))
 paths=[ROOT/'README.md',ROOT/'detections/savedsearches.conf',ROOT/'detections/c05_permission_grants.preview.spl',ROOT/'detections/c05_permission_grants.spl',ROOT/'lookups/entra_approved_grants.csv',ROOT/'docs/c05-detect-02-validation.md',*ROOT.glob('tools/c05_d2_*.py'),*[p for p in OUT.iterdir() if p.name!='sha256.json' and p.is_file()]]
 manifest={str(p.relative_to(ROOT)):sha(p) for p in sorted(paths)};(OUT/'sha256.json').write_text(json.dumps(manifest,indent=2)+'\n');print('MANIFEST',len(manifest))
elif sys.argv[1]=='export':
 manifest=json.loads((OUT/'sha256.json').read_text());assert all(sha(ROOT/p)==h for p,h in manifest.items())
 assert not git('status','--porcelain'),'working tree not clean'
 export=Path('/tmp/c05-d2-export');export.mkdir(exist_ok=True)
 head=git('rev-parse','HEAD').strip();binding={'task':'C05-DETECT-02 revision 1','branch':git('branch','--show-current').strip(),'base':'e1f33d34deb9ec9cdba5a71d29ce8405ede5bdca','head':head,'status':git('status','--short','--branch'),'publication':'local only; no push/PR/merge/tag','evidence':'implementation-captured, ready for independent review'}
 (export/'binding.json').write_text(json.dumps(binding,indent=2)+'\n')
 with tarfile.open(export/'c05-detect-02-evidence.tgz','w:gz') as tf:
  for p in [*manifest,'docs/evidence/c05-detect-02/sha256.json']:tf.add(ROOT/p,arcname=p)
  tf.add(export/'binding.json',arcname='binding.json')
 print(json.dumps(binding));print('ARCHIVE_SHA256',sha(export/'c05-detect-02-evidence.tgz'))
