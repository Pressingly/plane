/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

// types
import { API_BASE_URL } from "@plane/constants";
import type { ICsrfTokenData, IEmailCheckData, IEmailCheckResponse } from "@plane/types";
// helpers
import { buildOAuth2SignOutUrl } from "@/lib/oauth2-proxy";
// services
import { APIService } from "@/services/api.service";

export class AuthService extends APIService {
  constructor() {
    super(API_BASE_URL);
  }

  async requestCSRFToken(): Promise<ICsrfTokenData> {
    return this.get("/auth/get-csrf-token/")
      .then((response) => response.data)
      .catch((error) => {
        throw error;
      });
  }

  emailCheck = async (data: IEmailCheckData): Promise<IEmailCheckResponse> =>
    this.post("/auth/email-check/", data, { headers: {} })
      .then((response) => response?.data)
      .catch((error) => {
        throw error?.response?.data;
      });

  async sendResetPasswordLink(data: { email: string }): Promise<any> {
    return this.post(`/auth/forgot-password/`, data)
      .then((response) => response?.data)
      .catch((error) => {
        throw error?.response;
      });
  }

  async setPassword(token: string, data: { password: string }): Promise<any> {
    return this.post(`/auth/set-password/`, data, {
      headers: {
        "X-CSRFTOKEN": token,
      },
    })
      .then((response) => response?.data)
      .catch((error) => {
        throw error?.response?.data;
      });
  }

  async generateUniqueCode(data: { email: string }): Promise<any> {
    return this.post("/auth/magic-generate/", data, { headers: {} })
      .then((response) => response?.data)
      .catch((error) => {
        throw error?.response?.data;
      });
  }

  async signOut(_baseUrl: string): Promise<any> {
    // mPass SSO is the sole identity provider — full 3-layer logout via
    // oauth2-proxy sign_out → Cognito logout → app. The native Django
    // /auth/sign-out/ endpoint is no longer reachable in the SSO flow.
    if (typeof window === "undefined") return;
    window.location.href = buildOAuth2SignOutUrl(window.location.origin);
  }
}
