"""Hash review evidence only after acceptance assertions pass."""
from c05_alert_validation import *
assert json.loads((OUT/'acceptance.json').read_text())['all_passed']
assert command(['git','branch','--show-current'])['stdout'].strip()=='fix/c05-alert-trigger'
diff=command(['git','diff','9e7d5e1d7c5bf3598984b8d69b58ea23e548a4ee','--','detections/savedsearches.conf'])
assert diff['returncode']==0
(OUT/'savedsearches.diff').write_text(diff['stdout'])
files=[*OUT.glob('*'),*Path('tools').glob('*.py'),SOURCE,ROOT/'README.md',ROOT/'docs/c05-alerts-01-validation.md']
manifest={str(p.resolve().relative_to(ROOT)):sha(p) for p in files if p.is_file() and p.name!='sha256.json'}
save('sha256.json',{'algorithm':'sha256','files':dict(sorted(manifest.items()))})
print('HASHED_FILES',len(manifest))
