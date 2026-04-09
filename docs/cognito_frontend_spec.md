# Spec: mPass Cognito Auth — Frontend Redirects & Logout (PR 2)

## Overview

Four frontend changes wire the browser into the mPass oauth2-proxy flow:

1. **`oauth2-proxy.ts` helper** — centralises all oauth2-proxy URL construction
   and makes the base path configurable via `VITE_OAUTH2_PROXY_BASE_PATH`
   (default `/oauth2`).
2. **Authentication wrapper** — unauthenticated page loads redirect to
   `/oauth2/sign_in` instead of the native Plane login page.
3. **API 401 interceptor** — any API response that returns 401 redirects to
   `/oauth2/sign_in` so expired sessions are recovered automatically.
4. **3-layer logout** — `signOut()` clears Django session, then the
   `_oauth2_proxy` cookie, then the Cognito SSO session in sequence.

These changes are safe to ship before the Traefik + oauth2-proxy infrastructure
(PR 3) is in place: `/oauth2/sign_in` will 404 in dev until the proxy is
running, but the redirect target can be adjusted and the code path is unchanged.

---

## Spec Cases

### 1. oauth2-proxy URL helper — default base path

```
GIVEN  VITE_OAUTH2_PROXY_BASE_PATH is not set
WHEN   buildOAuth2SignInUrl or buildOAuth2SignOutUrl is called
THEN   the resulting URL starts with /oauth2/
```

### 2. oauth2-proxy URL helper — custom base path

```
GIVEN  VITE_OAUTH2_PROXY_BASE_PATH is set to "/auth/oauth2"
WHEN   buildOAuth2SignInUrl("http://localhost/issues/") is called
THEN   the resulting URL is /auth/oauth2/sign_in?rd=http%3A%2F%2F...
```

### 3. oauth2-proxy URL helper — normalisation

```
GIVEN  VITE_OAUTH2_PROXY_BASE_PATH is set to "oauth2/" (no leading slash, trailing slash)
WHEN   the helper normalises it
THEN   leading slash is added, trailing slash is removed → "/oauth2"
       AND resulting URL is /oauth2/sign_in?rd=...
```

### 4. oauth2-proxy URL helper — URL-like base path rejected

```
GIVEN  VITE_OAUTH2_PROXY_BASE_PATH is set to "https://evil.example.com/oauth2"
WHEN   the helper validates the value
THEN   isPathOnlyBasePath returns false
       AND base path falls back to "/oauth2"
       AND resulting URL is /oauth2/sign_in?rd=...
```

### 5. oauth2-proxy URL helper — protocol-relative base path rejected

```
GIVEN  VITE_OAUTH2_PROXY_BASE_PATH is set to "//evil.example.com/oauth2"
WHEN   the helper validates the value
THEN   isPathOnlyBasePath returns false
       AND base path falls back to "/oauth2"
```

### 6. oauth2-proxy URL helper — rd encoding

```
GIVEN  buildOAuth2SignInUrl is called with an unencoded URL
WHEN   the helper builds the URL
THEN   the rd parameter value is percent-encoded by the helper
       AND callers do not need to call encodeURIComponent themselves
```

### 7. Unauthenticated page load

```
GIVEN  the authentication wrapper renders
       AND the current user is not authenticated (no session)
WHEN   the wrapper evaluates auth state
THEN   window.location.href is set to buildOAuth2SignInUrl(window.location.href)
         i.e. /oauth2/sign_in?rd=<current URL, percent-encoded>
       AND no native Plane login page is rendered
```

### 8. rd parameter carries the full current URL (wrapper)

```
GIVEN  the user navigates to /projects/abc123/issues/
       AND is not authenticated
WHEN   the authentication wrapper redirects
THEN   rd equals encodeURIComponent(window.location.href)
       e.g. /oauth2/sign_in?rd=http%3A%2F%2Flocalhost%2Fprojects%2Fabc123%2Fissues%2F
```

### 9. API response returns 401

```
GIVEN  any API call returns HTTP 401
WHEN   the Axios response interceptor fires
THEN   window.location.replace is called with:
         <origin> + buildOAuth2SignInUrl(<path + search>)
         i.e. http://localhost/oauth2/sign_in?rd=%2Fissues%2F%3Ffilter%3Dopen
       AND the user is redirected to re-authenticate
```

### 10. 401 rd parameter carries path only (not full origin)

```
GIVEN  current page is http://localhost/issues/?filter=open
       AND an API call returns 401
WHEN   the interceptor fires
THEN   rd equals encodeURIComponent("/issues/?filter=open")
       (path + search only — origin is prepended separately outside the helper)
```

### 11. Sign-out — full 3-layer logout with OIDC env vars set

```
GIVEN  VITE_OIDC_LOGOUT_URL is set to a valid Cognito hosted-UI logout URL
       AND VITE_OIDC_CLIENT_ID is set
WHEN   signOut() is called
THEN   (Layer 1) POST /auth/sign-out/ is called to clear the Django session
       AND (Layer 2+3) window.location.href is set to:
             buildOAuth2SignOutUrl(<cognito-logout-url with client_id + logout_uri>)
             i.e. /oauth2/sign_out?rd=<cognito-logout-url, percent-encoded>
       WHERE cognito-logout-url has:
               client_id  = VITE_OIDC_CLIENT_ID
               logout_uri = window.location.origin
```

### 12. Sign-out — fallback when OIDC env vars absent

```
GIVEN  VITE_OIDC_LOGOUT_URL is not set (or VITE_OIDC_CLIENT_ID is not set)
WHEN   signOut() is called
THEN   (Layer 1) POST /auth/sign-out/ is called
       AND window.location.href is set to:
             buildOAuth2SignOutUrl(window.location.origin)
             i.e. /oauth2/sign_out?rd=<origin, percent-encoded>
       AND no attempt is made to build a Cognito logout URL
```

### 13. Sign-out — malformed OIDC logout URL

```
GIVEN  VITE_OIDC_LOGOUT_URL is set but is not a valid URL (e.g. "not-a-url")
WHEN   signOut() is called
THEN   the URL construction try-block catches the error
       AND falls back to buildOAuth2SignOutUrl(window.location.origin)
       AND no exception propagates to the caller
```

### 14. Sign-out — Django session failure does not block OIDC logout

```
GIVEN  POST /auth/sign-out/ throws a network error or returns an error status
WHEN   signOut() is called
THEN   the error is caught and swallowed
       AND resetOnSignOut() is still called
       AND the /oauth2/sign_out redirect still happens
       (try/catch/finally guarantees Layers 2+3 always run)
```

### 15. In-store state is reset before OIDC redirect

```
GIVEN  signOut() is called
WHEN   the sign-out sequence runs
THEN   this.store.resetOnSignOut() is called
       BEFORE window.location.href is set for the OIDC redirect
       AND the user's in-memory store state is cleared
```

---

## Files

| File                                                    | Change                                                                                                                           |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `apps/web/core/lib/oauth2-proxy.ts`                     | **New** — URL helpers: `buildOAuth2SignInUrl`, `buildOAuth2SignOutUrl`, configurable base path via `VITE_OAUTH2_PROXY_BASE_PATH` |
| `apps/web/core/lib/wrappers/authentication-wrapper.tsx` | Unauthenticated → `buildOAuth2SignInUrl(window.location.href)` (replaces `router.push`)                                          |
| `apps/web/core/services/api.service.ts`                 | 401 interceptor → `buildOAuth2SignInUrl(path+search)`                                                                            |
| `apps/web/core/store/user/index.ts`                     | `signOut()` — 3-layer logout, `try/catch/finally`, uses `buildOAuth2SignOutUrl`                                                  |
| `apps/web/.env.example`                                 | `VITE_OAUTH2_PROXY_BASE_PATH`, `VITE_OIDC_LOGOUT_URL`, `VITE_OIDC_CLIENT_ID`                                                     |

---

## Environment Variables

| Variable                      | Required | Purpose                                                                                     |
| ----------------------------- | -------- | ------------------------------------------------------------------------------------------- |
| `VITE_OAUTH2_PROXY_BASE_PATH` | No       | Path where oauth2-proxy is mounted (default `/oauth2`; URL-like values fallback to default) |
| `VITE_OIDC_LOGOUT_URL`        | No       | Cognito hosted-UI logout endpoint                                                           |
| `VITE_OIDC_CLIENT_ID`         | No       | Cognito app client ID (appended to logout URL)                                              |

`VITE_OIDC_LOGOUT_URL` and `VITE_OIDC_CLIENT_ID` default to empty. If absent,
logout still clears the Django session and `_oauth2_proxy` cookie; only the
Cognito SSO session persists.

---

## Logout Sequence (detail)

```
signOut()
  │
  ├─ try:  POST /auth/sign-out/             → clears Django session cookie
  ├─ catch: swallow error                   → Layer 2/3 must still run
  └─ finally:
       store.resetOnSignOut()               → clears in-memory state
       │
       └─ Layer 2+3 redirect:
            if VITE_OIDC_LOGOUT_URL && VITE_OIDC_CLIENT_ID:
                build cognito_logout_url = VITE_OIDC_LOGOUT_URL
                                             ?client_id=VITE_OIDC_CLIENT_ID
                                             &logout_uri=window.location.origin
                window.location.href = buildOAuth2SignOutUrl(cognito_logout_url)
                                              ↑ Layer 2: clears _oauth2_proxy cookie
                                                         then redirects to cognito_logout_url
                                                              ↑ Layer 3: clears Cognito SSO
            else:
                window.location.href = buildOAuth2SignOutUrl(window.location.origin)
```

---

## Branch

`feat/mpass-pr2-frontend` branched from `preview`
