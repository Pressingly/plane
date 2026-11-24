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
