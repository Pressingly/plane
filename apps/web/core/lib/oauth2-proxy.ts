/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

const DEFAULT_OAUTH2_PROXY_BASE_PATH = "/oauth2";

const isPathOnlyBasePath = (value: string): boolean => {
  if (value.startsWith("//")) return false;
  if (/^[a-z][a-z0-9+.-]*:\/{2}/i.test(value)) return false;
  return true;
};

const normaliseOAuth2ProxyBasePath = (basePath?: string): string => {
  const trimmed = basePath?.trim();
  if (!trimmed) return DEFAULT_OAUTH2_PROXY_BASE_PATH;
  if (!isPathOnlyBasePath(trimmed)) return DEFAULT_OAUTH2_PROXY_BASE_PATH;

  let normalised = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  while (normalised.length > 1 && normalised.endsWith("/")) {
    normalised = normalised.slice(0, -1);
  }

  return normalised;
};

export const getOAuth2ProxyBasePath = (): string =>
  normaliseOAuth2ProxyBasePath(import.meta.env.VITE_OAUTH2_PROXY_BASE_PATH);

const buildOAuth2ProxyPath = (action: "sign_in" | "sign_out"): string => `${getOAuth2ProxyBasePath()}/${action}`;

export const buildOAuth2SignInUrl = (rd: string): string =>
  `${buildOAuth2ProxyPath("sign_in")}?rd=${encodeURIComponent(rd)}`;

export const buildOAuth2SignOutUrl = (rd: string): string =>
  `${buildOAuth2ProxyPath("sign_out")}?rd=${encodeURIComponent(rd)}`;

const trimEnv = (v: string | undefined): string => (v ?? "").trim();

/**
 * Resolve the post-logout destination — the URL the browser lands on once
 * the Django session, oauth2-proxy session, and (optionally) Cognito session
 * have all been cleared.
 *
 * Order of preference:
 *  1. `VITE_LOGOUT_REDIRECT_URL` — explicit deploy-time knob.
 *  2. Strip the leftmost subdomain when the host has 2+ dots
 *     (e.g. `foss-pm.local.moneta.dev` → `local.moneta.dev`).
 *  3. Fall back to the current origin.
 *
 * The previous regex `^[^.]+\.(?=[^.]*\.[^.]*\.)/` required ≥4 segments and
 * silently misfired for `app.example.com` / `localhost`, leaving the user on
 * the same origin where ForwardAuth would immediately re-authenticate them.
 */
const buildPortalUrl = (): string => {
  if (typeof window === "undefined") return "/";
  const configured = trimEnv(import.meta.env.VITE_LOGOUT_REDIRECT_URL);
  if (configured) return configured;

  const { protocol, host, hostname } = window.location;
  const dotCount = (hostname.match(/\./g) || []).length;
  if (dotCount >= 2) {
    return `${protocol}//${host.replace(/^[^.]+\./, "")}`;
  }
  return `${protocol}//${host}`;
};

const buildCognitoLogoutUrl = (returnTo: string): string | null => {
  const logoutUrl = trimEnv(import.meta.env.VITE_OIDC_LOGOUT_URL);
  const clientId = trimEnv(import.meta.env.VITE_OIDC_CLIENT_ID);
  if (!logoutUrl || !clientId) return null;
  const params = new URLSearchParams({ client_id: clientId, logout_uri: returnTo });
  return `${logoutUrl}?${params.toString()}`;
};

/**
 * Build the URL that the SPA navigates to after the Django sign-out POST.
 *
 * SSO deploys: chain through `/oauth2/sign_out` so oauth2-proxy clears its
 * Redis-backed session; if Cognito logout creds are configured, oauth2-proxy
 * then redirects to Cognito which redirects to the portal — closing all
 * three session layers (Django, oauth2-proxy, Cognito).
 *
 * Non-SSO deploys: navigate straight to the portal URL.
 *
 * Replaces the previous host-rewrite regex which silently kept the browser
 * on the SSO-protected origin and caused immediate re-authentication via
 * Traefik ForwardAuth.
 */
export const buildLogoutDestination = (): string => {
  const portalUrl = buildPortalUrl();
  if (!trimEnv(import.meta.env.VITE_OAUTH2_PROXY_BASE_PATH)) return portalUrl;
  const cognitoUrl = buildCognitoLogoutUrl(portalUrl);
  return buildOAuth2SignOutUrl(cognitoUrl ?? portalUrl);
};
