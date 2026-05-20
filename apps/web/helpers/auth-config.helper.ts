/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

/** True when the web build is configured for SSO auth (VITE_AUTH_TYPE=SSO). */
export const isSsoAuth = (): boolean =>
  (import.meta.env.VITE_AUTH_TYPE?.toString() ?? "").trim().toUpperCase() === "SSO";
