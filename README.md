# EFMS – Event & Festival Management System

## Windows setup
1. Extract this folder completely.
2. Open PowerShell in the extracted folder.
3. Create a virtual environment and install dependencies:

```powershell
py -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

4. Create your private environment file:

```powershell
Copy-Item .env.example .env
```

5. Edit `.env` and set a fresh `SECRET_KEY`. Configure Gmail SMTP with a Google App Password if you want email verification and password recovery. Add your own Razorpay keys to enable real gateway checkout.
6. Start EFMS:

```powershell
.\venv\Scripts\python.exe app.py
```

7. Open http://127.0.0.1:5000

## Important
- Never share or upload `.env`.
- Back up `efms.db` before running database migrations.
- Email verification and password recovery require SMTP credentials.
- Read `UPGRADE_NOTES.md` for included changes and known remaining work.
