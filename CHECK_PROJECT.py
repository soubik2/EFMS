from pathlib import Path
import ast, re, sqlite3
root = Path(__file__).resolve().parent
ast.parse((root / 'app.py').read_text(encoding='utf-8'))
src = (root / 'app.py').read_text(encoding='utf-8')
required = sorted(set(re.findall(r"render_template\(['\"]([^'\"]+)", src)))
missing = [name for name in required if not (root / 'templates' / name).is_file()]
if missing:
    raise SystemExit('Missing templates: ' + ', '.join(missing))
if not (root / 'static' / 'css' / 'style.css').is_file():
    raise SystemExit('Missing static/css/style.css')
con = sqlite3.connect(root / 'efms.db')
status = con.execute('PRAGMA integrity_check').fetchone()[0]
con.close()
if status != 'ok':
    raise SystemExit('Database integrity check failed: ' + status)
print(f'OK: Python syntax; {len(required)} route templates; static CSS; SQLite integrity={status}')
