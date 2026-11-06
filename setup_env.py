from pathlib import Path
import secrets
p=Path(__file__).resolve().parent/'.env'
example=Path(__file__).resolve().parent/'.env.example'
if not p.exists():
    text=example.read_text(encoding='utf-8') if example.exists() else ''
    text=text.replace('replace-with-a-long-random-secret',secrets.token_urlsafe(48))
    p.write_text(text,encoding='utf-8')
    print('Created .env with a fresh local SECRET_KEY. Add integrations only if needed.')
else: print('.env already exists; leaving it unchanged.')
