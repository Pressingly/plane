# Spec: mPass Cognito Auth — Backend Middleware (PR 1)

## Overview

Reads `X-Auth-Request-Email` header (set by oauth2-proxy after Cognito
validation), finds or creates the Plane user, and establishes a native
Django session. No-op until Traefik + oauth2-proxy infrastructure is
in place (PR 3) — no behavioural change to existing Plane auth.

---

## Spec Cases

### 1. Already authenticated

```
GIVEN  request.user.is_authenticated is True
WHEN   middleware runs
THEN   no DB query, no login() call
       AND passes through immediately
```

### 2. No email header

```
GIVEN  X-Auth-Request-Email is absent
WHEN   middleware runs
THEN   passes through unauthenticated
       AND request.user remains AnonymousUser
```

### 3. Empty email after normalisation

```
GIVEN  X-Auth-Request-Email is present but normalises to empty string
WHEN   middleware runs
THEN   passes through unauthenticated
       AND no DB query, no login() call
```

### 4. Bypass paths

```
GIVEN  request path starts with /god-mode (e.g. /god-mode/setup/)
WHEN   middleware runs with a valid email header
THEN   no DB query, no login() call
       AND passes through unchanged
```

```
GIVEN  request path starts with /api/instances (e.g. /api/instances/config/)
WHEN   middleware runs with a valid email header
THEN   no DB query, no login() call
       AND passes through unchanged
```

### 5. New user

```
GIVEN  X-Auth-Request-Email is present
       AND no User exists for that email
WHEN   middleware runs
THEN   User created with:
         is_password_autoset = True
         is_email_verified   = True
         has_usable_password = False
         username            = uuid4().hex  (never the Cognito sub)
       AND Profile created for that user
       AND user_login(request=request, user=user, is_app=True) called
```

### 6. Existing user

```
GIVEN  X-Auth-Request-Email is present
       AND User already exists for that email
WHEN   middleware runs
THEN   no duplicate User created
       AND user_login() called with the existing user
```

### 7. Inactive user

```
GIVEN  User exists but is_active = False
WHEN   middleware runs with that user's email header
THEN   user_login() never called
       AND passes through unauthenticated
```

### 8. Email normalisation

```
GIVEN  X-Auth-Request-Email contains "  UPPER@EXAMPLE.COM  "
WHEN   middleware runs
THEN   email looked up as "upper@example.com"
       AND matches existing user (no duplicate created)
```

### 9. login() called with correct arguments

```
GIVEN  valid email header for any user
WHEN   middleware runs
THEN   user_login() called with:
         request = current request
         user    = resolved user
         is_app  = True
```

### 10. Race condition

```
GIVEN  get_or_create raises IntegrityError (concurrent insert)
       AND the user already exists in the DB
WHEN   middleware handles it
THEN   falls back to get(email=email)
       AND user_login() still called
       AND no exception propagates
```

---

## Files

| File                                                           | Purpose                                                 |
| -------------------------------------------------------------- | ------------------------------------------------------- |
| `apps/api/plane/authentication/middleware/proxy_auth.py`       | Middleware implementation                               |
| `apps/api/plane/authentication/middleware/proxy_auth_utils.py` | Helper functions: normalise, bypass check, coerce paths |
| `apps/api/plane/authentication/tests/test_proxy_auth.py`       | Tests for cases 1–10 above                              |
| `apps/api/plane/authentication/tests/test_proxy_auth_core.py`  | Pure Python tests for helper functions                  |
| `apps/api/plane/settings/common.py`                            | `MPASS_BYPASS_PATHS`, middleware registration           |

## Running tests

```bash
cd apps/api

# All proxy auth tests
pytest plane/authentication/tests/ -v

# Middleware tests only
pytest plane/authentication/tests/test_proxy_auth.py -v

# Helper function tests (no DB required)
pytest plane/authentication/tests/test_proxy_auth_core.py -v
```
