# CLAUDE.md — mPass OIDC Integration (Plane)

## Project Overview

We are integrating mPass (AWS Cognito OIDC) as the sole login method for Plane.
Plane sits behind a Traefik reverse proxy. We use oauth2-proxy as a centralised
authentication gateway. The approach requires a **fork** of Plane — changes are
small (~20 lines across 5 files) and unlikely to conflict on upstream upgrades.

---

## Architecture

```
Browser
  ↓
Traefik (port 80)
  ↓  ForwardAuth middleware on /api/* and /auth/*
oauth2-proxy  →  validates _oauth2_proxy session cookie against Cognito
  ↓  sets headers on success:
     X-Auth-Request-Email   (user's email)
     X-Auth-Request-User    (Cognito sub)
  ↓
Django API
  ↓
ProxyAuthMiddleware  →  reads headers, get_or_create user, login()
  ↓
Native Django session established
```

---

## Authentication Flow

1. Browser hits `http://localhost/` → Traefik routes to frontend
2. Frontend calls `/api/users/me/` → Traefik ForwardAuth runs
3. No `_oauth2_proxy` cookie → oauth2-proxy redirects to Cognito login
4. User authenticates → oauth2-proxy sets `_oauth2_proxy` cookie → redirects back
5. Cookie valid → oauth2-proxy returns 202 with `X-Auth-Request-Email` header
6. Traefik forwards request + headers to Django API
7. `ProxyAuthMiddleware` reads email, finds/creates user, calls `user_login()`
8. Django session cookie set in response
9. Subsequent requests: Django session handles auth; ForwardAuth still validates
   oauth2-proxy cookie in background

---

## Logout Flow

Three layers must be cleared in sequence:

| Layer | What                   | How                                                                |
| ----- | ---------------------- | ------------------------------------------------------------------ |
| 1     | Django session         | `POST /auth/sign-out/` (Plane native logout)                       |
| 2     | `_oauth2_proxy` cookie | `GET /oauth2/sign_out`                                             |
| 3     | Cognito SSO session    | `GET https://<cognito-domain>/logout?client_id=...&logout_uri=...` |

Frontend `signOut()` in `apps/web/core/store/user/index.ts` handles all 3.
Cognito logout URL is driven by `VITE_OIDC_LOGOUT_URL` and `VITE_OIDC_CLIENT_ID`
in `apps/web/.env`.

**Cognito requirement:** `http://localhost` (dev) or `https://<plane-host>` (prod)
must be registered as an **Allowed sign-out URL** in the Cognito app client.

---

## Session Layers

- **Layer 1**: `_oauth2_proxy` cookie — managed by oauth2-proxy, stored in Redis
- **Layer 2**: Django session cookie — managed by Plane's native session middleware

oauth2-proxy session is stored in Redis (not cookies) to avoid the 4 KB cookie
size limit caused by large Cognito JWTs.

---

## Files Changed in This Fork

### Backend

| File                                                          | Change                                                                                                |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `apps/api/plane/authentication/middleware/proxy_auth.py`      | **New** — ProxyAuthMiddleware                                                                         |
| `apps/api/plane/authentication/tests/test_proxy_auth.py`      | **New** — middleware tests                                                                            |
| `apps/api/plane/authentication/tests/test_proxy_auth_core.py` | **New** — helper function tests                                                                       |
| `apps/api/plane/settings/common.py`                           | +2 settings: `MPASS_PROXY_AUTH_ENABLED`, `MPASS_BYPASS_PATHS` + middleware added to `MIDDLEWARE` list |
| `apps/api/.env`                                               | OIDC credentials + `OAUTH2_PROXY_COOKIE_SECRET`                                                       |

### Frontend

| File                                                    | Change                                        |
| ------------------------------------------------------- | --------------------------------------------- |
| `apps/web/core/store/user/index.ts`                     | `signOut()` clears all 3 logout layers        |
| `apps/web/core/lib/wrappers/authentication-wrapper.tsx` | Unauthenticated → `/oauth2/sign_in?rd=...`    |
| `apps/web/core/services/api.service.ts`                 | 401 interceptor → `/oauth2/sign_in?rd=...`    |
| `apps/web/.env`                                         | `VITE_OIDC_LOGOUT_URL`, `VITE_OIDC_CLIENT_ID` |
| `apps/web/vite.config.ts`                               | Dev proxy: `/oauth2` → `http://localhost:80`  |

### Infrastructure

| File                         | Change                                           |
| ---------------------------- | ------------------------------------------------ |
| `config/traefik/traefik.yml` | Entrypoints, dashboard                           |
| `config/traefik/dynamic.yml` | ForwardAuth middleware, routers, services        |
| `docker-compose-local.yml`   | Traefik, oauth2-proxy (with Redis session store) |

---

## Environment Variables

### Backend — `apps/api/.env`

| Variable                     | Purpose                                                                           |
| ---------------------------- | --------------------------------------------------------------------------------- |
| `OIDC_BASE_URI`              | Cognito issuer URL (e.g. `https://cognito-idp.us-east-1.amazonaws.com/<pool-id>`) |
| `OIDC_CLIENT_ID`             | Cognito app client ID                                                             |
| `OIDC_CLIENT_SECRET`         | Cognito app client secret                                                         |
| `OAUTH2_PROXY_COOKIE_SECRET` | 32-byte base64 secret for oauth2-proxy cookie signing                             |
| `MPASS_PROXY_AUTH_ENABLED`   | `1` (default) to enable, `0` to disable middleware kill switch                    |
| `MPASS_BYPASS_PATHS`         | Comma-separated paths to skip auth (default: `/god-mode,/api/instances`)          |

### Frontend — `apps/web/.env`

| Variable               | Purpose                           |
| ---------------------- | --------------------------------- |
| `VITE_OIDC_LOGOUT_URL` | Cognito hosted UI logout endpoint |
| `VITE_OIDC_CLIENT_ID`  | Cognito app client ID             |

---

## Bypass Routes (No Auth)

| Path               | Reason                                 |
| ------------------ | -------------------------------------- |
| `/god-mode/*`      | Admin panel uses local email/password  |
| `/api/instances/*` | Instance admin endpoints               |
| `/oauth2/*`        | oauth2-proxy handles its own auth flow |
| `OPTIONS` requests | CORS preflight                         |

---

## Cognito App Client Requirements

- **Allowed callback URLs:** `http://localhost/oauth2/callback`
- **Allowed sign-out URLs:** `http://localhost`
- **OAuth grant types:** Authorization code grant
- **Scopes:** `openid profile email`

---

## Local Development

### Start infrastructure

```bash
docker compose -f docker-compose-local.yml up -d
```

### Start frontend

```bash
pnpm --filter web dev
```

### Access

- App: `http://localhost`
- Traefik dashboard: `http://localhost:8080`

### Common gotcha — stale container environment

If middleware appears disabled (`enabled=False` in logs), the container has a
stale env var from a previous run. Fix with:

```bash
docker compose -f docker-compose-local.yml up -d --force-recreate api
```

### Test with curl

```bash
# Simulate authenticated request — port 8000 is localhost-only so this only
# works from the same machine (bypasses ForwardAuth, for debugging only)
curl -H "X-Auth-Request-Email: user@example.com" http://localhost:8000/api/users/me/

# Test bypass route
curl http://localhost:8000/api/instances/
```

---

## Running Tests

```bash
cd apps/api

# All proxy auth tests
pytest plane/authentication/tests/ -v

# Middleware behaviour tests only
pytest plane/authentication/tests/test_proxy_auth.py -v

# Helper function tests only (no DB required)
pytest plane/authentication/tests/test_proxy_auth_core.py -v
```

### What the tests cover

**`test_proxy_auth.py`** — ProxyAuthMiddleware contract:

- Kill switch (`MPASS_PROXY_AUTH_ENABLED=False`) disables middleware entirely
- Existing Django session is never touched
- Missing email header → pass through unauthenticated
- First-seen email → creates User + Profile, UUID username, unusable password
- Known email → finds existing user, no duplicate created
- Inactive user → passes through unauthenticated
- `user_login()` called with correct args (`request`, `user`, `is_app=True`)
- Bypass paths (`/god-mode`, `/api/instances`) skip DB and login entirely
- Email normalised (lowercase + strip) before DB lookup
- `IntegrityError` race condition handled gracefully

**`test_proxy_auth_core.py`** — Helper functions (pure Python, no DB):

- `_normalise_email` — lowercases and strips
- `_is_bypass_path` — exact match, prefix match, segment boundary enforcement
- `_coerce_bypass_paths` — None/empty → defaults, string → list, tuple → list

---

## Security Notes

- Traefik ForwardAuth **overwrites** client-supplied `X-Auth-Request-*` headers —
  header spoofing is not possible on protected routes
- Bypass routes skip ForwardAuth entirely — god-mode retains local credentials
- Users created via proxy auth have `set_unusable_password()` — cannot log in via password
- oauth2-proxy session stored in Redis to avoid 4 KB cookie split issues with Cognito JWTs
- `MPASS_PROXY_AUTH_ENABLED=0` is a kill switch — disables auth without removing infrastructure
- API port 8000 bound to `127.0.0.1` only — external machines on the same network cannot
  bypass Traefik/ForwardAuth by hitting port 8000 directly

---

## Why Not a PyPI Package?

A `mpass-proxy-auth` package was considered to avoid forking. It works cleanly
for the backend (inject middleware via custom settings, no source changes). But
the frontend changes (logout flow, 401 redirect) still require patching Plane's
compiled JS — so you end up with both a package and a fork. A single fork is
simpler to maintain.

---

## Cognito Details (Dev Environment)

```
Region:        us-east-1
User Pool ID:  us-east-1_TnhwOUxD0
Issuer URL:    https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TnhwOUxD0
Hosted UI:     https://us-east-1tnhwouxd0.auth.us-east-1.amazoncognito.com
```
