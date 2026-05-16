#!/usr/bin/env bash
#
# sso-audit.sh — Plane-side fork audit against the cross-app SSO contract.
#
# ============================================================================
# Covers the fork-side rows of awais786/sso-rules-moneta:openspec/specs/
# proxy-auth-middleware/spec.md that a deterministic bash check can verify
# against Plane's source tree. Catches regressions BEFORE they reach
# foss-server-bundle-devstack, where the same rows currently emit `?` (no
# fork code on disk in the bundle CI).
#
# Together with the bundle-side audit (foss-server-bundle-devstack/scripts/
# audit-sso.sh), the contract is now ~14 of 21 rows deterministic without
# any LLM invocation. The remaining rows (identity-managed UI gating,
# display-name UUID check) need either runtime SSO state or AST-level
# semantic analysis — those defer to the LLM-backed
# /sso-rules:audit-all-apps slash command.
#
# Exit codes:
#   0 — all rows ✅ or n/a / informational
#   1 — at least one SECURITY-CRITICAL row failed (today: row 20 session-
#       identity reconciliation). These violations re-open the cross-user
#       identity-leak class of bug.
#
# Rows covered:
#   Row 14 — logout shape: SPA logout MUST NOT call /oauth2/sign_out, MUST
#            redirect to portal host (env-supplied or 4-label regex), MUST
#            NOT POST /auth/sign-out/ (per logout-flow spec §"Per-app
#            'Logout' SHALL be navigation-only"; tolerated as drift today).
#   Row 20 — session-identity reconciliation (Rule 2 mismatch flush):
#            proxy_auth.py MUST call django.contrib.auth.logout(request)
#            on identity mismatch. Without this, the stale-session-on-user-
#            switch leak returns.  SECURITY-CRITICAL.
#   Row 21 — email-shape detection MUST NOT use polynomial-backtracking
#            regex. Plane uses substring check today, so this row is
#            informational — the audit fires only if a regex is reintroduced.
#
# Source of truth: awais786/sso-rules-moneta:openspec/specs/proxy-auth-
# middleware/spec.md. When upstream adds a new fork-side row, vendor the
# updated check here.
# ============================================================================

set -euo pipefail

PROXY_AUTH="apps/api/plane/authentication/middleware/proxy_auth.py"
PROXY_AUTH_UTILS="apps/api/plane/authentication/middleware/proxy_auth_utils.py"
LOGOUT_SPA="apps/web/core/store/user/index.ts"

# Output state — populated by each check_row_N function, printed at the end.
declare -a ROW_STATUS=()
declare -a ROW_TITLES=(
  "logout shape: no /oauth2/sign_out, navigation-only redirect"
  "session-identity reconciliation present (Rule 2 mismatch flush)"
  "email-shape detection uses substring/indexOf, not polynomial regex"
)
declare -a ROW_NOTES=()

# Row numbers per the cross-app SKILL.md §5 table. We only emit a subset
# here; bundle CI emits 1-21.
declare -a ROW_NUMBERS=(14 20 21)

# Security-critical row indices (0-indexed into ROW_NUMBERS above).
SECURITY_CRITICAL=(1)   # index 1 → row 20

SECURITY_CRITICAL_FAILS=0

record() {
  local idx=$1 status=$2 note=$3
  ROW_STATUS[$idx]="$status"
  ROW_NOTES[$idx]="$note"
  if [[ "$status" == "❌" ]]; then
    for c in "${SECURITY_CRITICAL[@]}"; do
      if [[ "$c" -eq "$idx" ]]; then
        SECURITY_CRITICAL_FAILS=$((SECURITY_CRITICAL_FAILS + 1))
        return
      fi
    done
  fi
}

# ============================================================================
# Row 14 (idx 0): logout shape
#
# SPA logout MUST NOT contain `/oauth2/sign_out` literal — the bundle's
# logout model is navigation-only. Per logout-flow §"Per-app 'Logout' SHALL
# be navigation-only", a future ideal also drops the POST /auth/sign-out/
# call, but that's tolerated drift today, so we don't fail on it.
# ============================================================================
check_row_14() {
  if [[ ! -f "$LOGOUT_SPA" ]]; then
    record 0 "?" "$LOGOUT_SPA not found — skipping"
    return
  fi

  if grep -qE '/oauth2/sign_?out' "$LOGOUT_SPA"; then
    local line
    line=$(grep -nE '/oauth2/sign_?out' "$LOGOUT_SPA" | head -1)
    record 0 "❌" "Logout calls \`/oauth2/sign_out\` at $LOGOUT_SPA:$line — per logout-flow spec, per-app Logout is navigation-only. Drop the call; portal 'Logout all' handles oauth2-proxy clearing."
    return
  fi

  record 0 "✅" "$LOGOUT_SPA does not invoke \`/oauth2/sign_out\` — navigation-only logout shape preserved"
}

# ============================================================================
# Row 20 (idx 1): session-identity reconciliation
#
# proxy_auth.py MUST call django.contrib.auth.logout(request) (imported as
# `logout` or aliased) on identity mismatch. The presence of the import +
# call is the deterministic signal; the bash audit can't verify the call
# site's *position* relative to the mismatch detection, only that it exists.
# That's a spec-conformance approximation; the test suite at
# apps/api/plane/authentication/tests/test_proxy_auth.py pins the exact
# behaviour.
#
# SECURITY-CRITICAL: without this call, the stale-session leak returns.
# ============================================================================
check_row_20() {
  if [[ ! -f "$PROXY_AUTH" ]]; then
    record 1 "?" "$PROXY_AUTH not found — skipping"
    return
  fi

  # Detect either `from django.contrib.auth import logout` (any form) or
  # an aliased import that brings `logout` into scope, plus a call site.
  local has_import
  has_import=$(grep -cE '^from django\.contrib\.auth import (.*\b)?logout(\b.*)?$|^from django\.contrib\.auth import logout as ' "$PROXY_AUTH" || true)

  local has_call
  has_call=$(grep -cE '\blogout\(request\)|\bdjango_logout\(request\)' "$PROXY_AUTH" || true)

  if [[ "$has_import" -gt 0 && "$has_call" -gt 0 ]]; then
    record 1 "✅" "django.contrib.auth.logout imported and invoked at least once in $PROXY_AUTH — Rule 2 mismatch flush in place"
    return
  fi

  if [[ "$has_import" -eq 0 ]]; then
    record 1 "❌" "$PROXY_AUTH does NOT import django.contrib.auth.logout. The cross-app spec (proxy-auth-middleware Rule 2) requires the middleware to call logout(request) when the proxy header asserts a different identity than the existing Django session. Without it, the stale-session-on-user-switch leak returns. Fix: add \`from django.contrib.auth import logout\` (or aliased) AND invoke \`logout(request)\` immediately on mismatch, before any bail-out path."
    return
  fi

  record 1 "❌" "$PROXY_AUTH imports django.contrib.auth.logout but never calls it. Fix: invoke \`logout(request)\` on identity mismatch before falling through to the unauthenticated path."
}

# ============================================================================
# Row 21 (idx 2): polynomial-regex avoidance in email-shape detection
#
# Plane uses substring check (`"@" in email`) today, so this is a regression
# guard. The audit fires only if a Python regex matching the unanchored
# `[^\s@]+@[^\s@]+\.[^\s@]+` pattern is introduced. CodeQL's
# `py/polynomial-redos` (or `js/polynomial-redos`) flags this on adversarial
# input.
# ============================================================================
check_row_21() {
  local files=()
  [[ -f "$PROXY_AUTH" ]] && files+=("$PROXY_AUTH")
  [[ -f "$PROXY_AUTH_UTILS" ]] && files+=("$PROXY_AUTH_UTILS")

  if [[ ${#files[@]} -eq 0 ]]; then
    record 2 "?" "No proxy_auth files found — skipping"
    return
  fi

  # Look for the canonical polynomial-backtracking shape:
  #   [^\s@]+@[^\s@]+\.[^\s@]+
  # in any of the inspected files. Allow trivial whitespace variations.
  local hits
  hits=$(grep -nE '\[\^[\\\\]s@\]\+@\[\^[\\\\]s@\]\+\\\.\[\^[\\\\]s@\]\+' "${files[@]}" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    record 2 "❌" "Polynomial-backtracking email-shape regex detected: $hits. Rewrite to indexOf/substring-based check per openspec proxy-auth-middleware §'email-shape detection SHALL avoid polynomial-backtracking regex'. Reference: Outline's normalizeProxyEmail in Pressingly/outline#19."
    return
  fi

  record 2 "✅" "No polynomial-backtracking email-shape regex in ${files[*]}; using substring check or other O(n) detection"
}

# ============================================================================
# Run checks
# ============================================================================
check_row_14
check_row_20
check_row_21

# ============================================================================
# Print table
# ============================================================================
echo "## Plane SSO Fork Audit"
echo
echo "Cross-app contract: \`awais786/sso-rules-moneta:openspec/specs/proxy-auth-middleware/spec.md\`"
echo "Row numbers match \`skills/app-rules/SKILL.md\` §5 (the 21-row table)."
echo
echo "| Row | Invariant | Status | Notes |"
echo "|-----|-----------|--------|-------|"
for i in "${!ROW_TITLES[@]}"; do
  printf "| %d | %s | %s | %s |\n" \
    "${ROW_NUMBERS[$i]}" "${ROW_TITLES[$i]}" "${ROW_STATUS[$i]:-?}" "${ROW_NOTES[$i]:-}"
done
echo

# ============================================================================
# Summary + exit code
# ============================================================================
TOTAL_FAILS=0
for s in "${ROW_STATUS[@]}"; do
  [[ "$s" == "❌" ]] && TOTAL_FAILS=$((TOTAL_FAILS + 1))
done

if [[ "$TOTAL_FAILS" -eq 0 ]]; then
  echo "**All fork-side invariants hold.**"
  exit 0
fi

echo "**$TOTAL_FAILS violations.** Security-critical (row 20): $SECURITY_CRITICAL_FAILS."
if [[ "$SECURITY_CRITICAL_FAILS" -gt 0 ]]; then
  exit 1
fi
exit 0
