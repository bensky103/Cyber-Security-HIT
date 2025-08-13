# Cyber Security Project – Quick Guide

Single backend on port 5000. Switch between secure (patched) and vulnerable modes with APP_MODE. Cosmetic `/vuln/*` aliases work in both.

## 1) What is this
- Secure Flask API in `patched/`, vulnerable API in `vuln/` for comparison.
- Next.js frontend in `frontend/` (proxies `/api/*` to BACKEND_ORIGIN).
- SQLite by default (`./app.db`). OpenAPI spec in `api-contract/openapi.yaml`.

## 2) Run it (PowerShell)
Backend (one server on one port):
```powershell
pip install -r requirements.txt
python run.py                      # secure (default)

For Vulnerable mode, change in frontend/.env.local NEXT_PUBLIC_VULN_MODE to true
python run.py  # vulnerable (same port)

```
Frontend:
```
cd frontend

npm run dev
```


URLs: Backend http://localhost:5000  •  Frontend http://localhost:3000

## 3) Code map
- `patched/app_fixed.py` secure app; `vuln/app.py` vulnerable app
- `run.py` unified launcher; `frontend/next.config.mjs` proxy + headers

## 4) Docs
- API: `api-contract/openapi.yaml`
- Tests: `tests/` (pytest)

That’s it—run one backend on 5000, flip NEXT_PUBLIC_VULN_MODE to compare behaviors, and use the frontend via `/api/*`.

## 5) Security checks (XSS + SQLi) — quick checklist

- Important: Run backend in vulnerable mode for these demos.
	- PowerShell: `$env:APP_MODE = "vuln"; python run.py`

XSS Stored (Part A §4)
- Where in code: `vuln/routes/ticket_routes.py` add_comment() and get_comments()
- How to test:
	- Login (vuln) and get Bearer token.
	- POST `/vuln/tickets/{id}/comments` with `{ "content": "<img src=x onerror=alert(1)>" }`.
	- GET `/vuln/tickets/{id}/comments` and see raw HTML returned (stored XSS).
- Fix idea: Sanitize/encode on server before storing/returning (e.g., bleach) and/or sanitize on client (DOMPurify); avoid dangerouslySetInnerHTML.

SQL Injection (Part A §1 + §3 + §4)
- Auth (vulnerable): `vuln/auth/auth_handler.py` login() uses string-concatenated SQL.
	- Test: POST `/vuln/auth/login` with username like `admin'--` (any password) or `' OR 1=1 --`.
	- Expect (vuln): possible bypass/odd behavior. Secure mode should reject.
- Section §3/§4 endpoints here use ORM/stored procedures, so SQLi attempts should not alter queries.
- Fix idea: use bound parameters or stored procedures everywhere; replace the raw SQL in vuln login.

### How to run and test (PowerShell, Python, UI)

Start services (vulnerable mode)

```powershell
# Backend (vuln on port 5000)
cd "c:\Users\guyben\Desktop\Cyber security project HIT"
$env:APP_MODE = "vuln"; python run.py

# Frontend (vuln UI pointing to same backend)
cd "c:\Users\guyben\Desktop\Cyber security project HIT\frontend"
$env:BACKEND_ORIGIN = "http://localhost:5000"
$env:NEXT_PUBLIC_VULN_MODE = "true"
npm run dev
```

XSS Stored (tickets comments)

PowerShell (API)

```powershell
# 1) Register or login to get JWT
$regBody = @{ username="testuser"; email="test@example.com"; password="Test@Pass123" } | ConvertTo-Json
try { Invoke-RestMethod -Uri "http://localhost:5000/vuln/auth/register" -Method Post -Body $regBody -ContentType "application/json" | Out-Null } catch {}
$loginBody = @{ username="testuser"; password="Test@Pass123" } | ConvertTo-Json
$login = Invoke-RestMethod -Uri "http://localhost:5000/vuln/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
$token = $login.jwt_token

# 2) Post a malicious comment to an existing ticket (replace 1 with a real ticket id)
$commentBody = @{ content = '<img src=x onerror=alert(1)>' } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/vuln/tickets/1/comments" -Method Post -Headers @{ Authorization = "Bearer $token" } -Body $commentBody -ContentType "application/json"

# 3) Fetch comments (note raw HTML present)
Invoke-RestMethod -Uri "http://localhost:5000/vuln/tickets/1/comments" -Method Get -Headers @{ Authorization = "Bearer $token" }
```

Python (API)

```python
import requests
base = "http://localhost:5000"
requests.post(f"{base}/vuln/auth/register", json={"username":"testuser","email":"test@example.com","password":"Test@Pass123"})
login = requests.post(f"{base}/vuln/auth/login", json={"username":"testuser","password":"Test@Pass123"}).json()
hdrs = {"Authorization": f"Bearer {login['jwt_token']}"}
requests.post(f"{base}/vuln/tickets/1/comments", json={"content":"<img src=x onerror=alert(1)>"}, headers=hdrs)
print(requests.get(f"{base}/vuln/tickets/1/comments", headers=hdrs).json())
```

UI verification

- In the frontend (vuln), log in as the same user.
- Go to Tickets, open a ticket, add the payload `<img src=x onerror=alert(1)>` as a comment.
- Reload the ticket details/comments: an alert should trigger (stored XSS) in vulnerable mode.

SQL injection (login)

PowerShell (API)

```powershell
$body1 = @{ username="admin'--"; password="anything" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/vuln/auth/login" -Method Post -Body $body1 -ContentType "application/json"

$body2 = @{ username="' OR 1=1 --"; password="x" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/vuln/auth/login" -Method Post -Body $body2 -ContentType "application/json"
```

Python (API)

```python
import requests
base = "http://localhost:5000"
print(requests.post(f"{base}/vuln/auth/login", json={"username":"admin'--","password":"x"}).status_code)
print(requests.post(f"{base}/vuln/auth/login", json={"username":"' OR 1=1 --","password":"x"}).status_code)
```

UI verification

- On the frontend login page (vuln), try username `admin'--` with any password, or `' OR 1=1 --` with any password.
- Vulnerable mode may show unexpected success/behavior; secure mode should reject.

## 6) Swagger/OpenAPI
- Built‑in docs: http://localhost:5000/docs (secure or vuln mode, same port)
- Raw spec: http://localhost:5000/openapi.yaml (served from `api-contract/openapi.yaml`)
- If you changed PORT, replace 5000 accordingly.

## 7) Config (where and how)
- App config code: `patched/config/config.py` (reads env vars). Common envs: `DATABASE_URL`, `JWT_SECRET`, `PEPPER_SECRET`.
- Password policy is stored in DB table `config` (name='password_policy'), created by `patched/config/setup.py`. Update its JSON value to change rules.
