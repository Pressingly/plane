# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.urls import path

from .views import (
    CSRFTokenEndpoint,
    PortalSignOutEndpoint,
    SignOutAuthEndpoint,
    SignOutAuthSpaceEndpoint,
)

# mPass SSO: native auth endpoints are disabled because oauth2-proxy
# ForwardAuth is the sole login method. Commented out (not deleted)
# so they can be restored if mPass is removed.
#
# Disabled imports:
# ForgotPasswordEndpoint, SetUserPasswordEndpoint, ResetPasswordEndpoint,
# ChangePasswordEndpoint, EmailCheckEndpoint,
# SignInAuthEndpoint, SignUpAuthEndpoint, MagicGenerateEndpoint,
# MagicSignInEndpoint, MagicSignUpEndpoint,
# GoogleOauthInitiateEndpoint, GoogleCallbackEndpoint,
# GitHubOauthInitiateEndpoint, GitHubCallbackEndpoint,
# GitLabOauthInitiateEndpoint, GitLabCallbackEndpoint,
# GiteaOauthInitiateEndpoint, GiteaCallbackEndpoint,
# SignInAuthSpaceEndpoint, SignUpAuthSpaceEndpoint,
# EmailCheckSpaceEndpoint, ForgotPasswordSpaceEndpoint,
# ResetPasswordSpaceEndpoint, MagicGenerateSpaceEndpoint,
# MagicSignInSpaceEndpoint, MagicSignUpSpaceEndpoint,
# GoogleOauthInitiateSpaceEndpoint, GoogleCallbackSpaceEndpoint,
# GitHubOauthInitiateSpaceEndpoint, GitHubCallbackSpaceEndpoint,
# GitLabOauthInitiateSpaceEndpoint, GitLabCallbackSpaceEndpoint,
# GiteaOauthInitiateSpaceEndpoint, GiteaCallbackSpaceEndpoint,

urlpatterns = [
    # signout — kept active (used by frontend 3-layer logout)
    path("sign-out/", SignOutAuthEndpoint.as_view(), name="sign-out"),
    path("spaces/sign-out/", SignOutAuthSpaceEndpoint.as_view(), name="space-sign-out"),
    # portal-driven signout — GET-able, CSRF-exempt, used by the foss-bundle
    # portal's "Log out of all apps" redirect chain to clear the Django
    # session cookie while the browser is on this app's domain.
    path(
        "portal-sign-out/",
        PortalSignOutEndpoint.as_view(),
        name="portal-sign-out",
    ),
    # csrf token — kept active (Django forms need it)
    path("get-csrf-token/", CSRFTokenEndpoint.as_view(), name="get_csrf_token"),

    # =========================================================================
    # mPass SSO: all native auth routes below are commented out.
    # oauth2-proxy ForwardAuth handles login via Cognito.
    # god-mode (/god-mode/*) bypasses ForwardAuth and uses local admin login.
    # =========================================================================

    # # credentials
    # path("sign-in/", SignInAuthEndpoint.as_view(), name="sign-in"),
    # path("sign-up/", SignUpAuthEndpoint.as_view(), name="sign-up"),
    # path("spaces/sign-in/", SignInAuthSpaceEndpoint.as_view(), name="space-sign-in"),
    # path("spaces/sign-up/", SignUpAuthSpaceEndpoint.as_view(), name="space-sign-up"),
    # # Magic sign in
    # path("magic-generate/", MagicGenerateEndpoint.as_view(), name="magic-generate"),
    # path("magic-sign-in/", MagicSignInEndpoint.as_view(), name="magic-sign-in"),
    # path("magic-sign-up/", MagicSignUpEndpoint.as_view(), name="magic-sign-up"),
    # path("spaces/magic-generate/", MagicGenerateSpaceEndpoint.as_view(), name="space-magic-generate"),
    # path("spaces/magic-sign-in/", MagicSignInSpaceEndpoint.as_view(), name="space-magic-sign-in"),
    # path("spaces/magic-sign-up/", MagicSignUpSpaceEndpoint.as_view(), name="space-magic-sign-up"),
    # ## Google Oauth
    # path("google/", GoogleOauthInitiateEndpoint.as_view(), name="google-initiate"),
    # path("google/callback/", GoogleCallbackEndpoint.as_view(), name="google-callback"),
    # path("spaces/google/", GoogleOauthInitiateSpaceEndpoint.as_view(), name="space-google-initiate"),
    # path("spaces/google/callback/", GoogleCallbackSpaceEndpoint.as_view(), name="space-google-callback"),
    # ## Github Oauth
    # path("github/", GitHubOauthInitiateEndpoint.as_view(), name="github-initiate"),
    # path("github/callback/", GitHubCallbackEndpoint.as_view(), name="github-callback"),
    # path("spaces/github/", GitHubOauthInitiateSpaceEndpoint.as_view(), name="space-github-initiate"),
    # path("spaces/github/callback/", GitHubCallbackSpaceEndpoint.as_view(), name="space-github-callback"),
    # ## Gitlab Oauth
    # path("gitlab/", GitLabOauthInitiateEndpoint.as_view(), name="gitlab-initiate"),
    # path("gitlab/callback/", GitLabCallbackEndpoint.as_view(), name="gitlab-callback"),
    # path("spaces/gitlab/", GitLabOauthInitiateSpaceEndpoint.as_view(), name="space-gitlab-initiate"),
    # path("spaces/gitlab/callback/", GitLabCallbackSpaceEndpoint.as_view(), name="space-gitlab-callback"),
    # ## Gitea Oauth
    # path("gitea/", GiteaOauthInitiateEndpoint.as_view(), name="gitea-initiate"),
    # path("gitea/callback/", GiteaCallbackEndpoint.as_view(), name="gitea-callback"),
    # path("spaces/gitea/", GiteaOauthInitiateSpaceEndpoint.as_view(), name="space-gitea-initiate"),
    # path("spaces/gitea/callback/", GiteaCallbackSpaceEndpoint.as_view(), name="space-gitea-callback"),
    # # Email Check
    # path("email-check/", EmailCheckEndpoint.as_view(), name="email-check"),
    # path("spaces/email-check/", EmailCheckSpaceEndpoint.as_view(), name="email-check"),
    # # Password
    # path("forgot-password/", ForgotPasswordEndpoint.as_view(), name="forgot-password"),
    # path("reset-password/<uidb64>/<token>/", ResetPasswordEndpoint.as_view(), name="forgot-password"),
    # path("spaces/forgot-password/", ForgotPasswordSpaceEndpoint.as_view(), name="space-forgot-password"),
    # path("spaces/reset-password/<uidb64>/<token>/", ResetPasswordSpaceEndpoint.as_view(), name="space-forgot-password"),  # noqa: E501
    # path("change-password/", ChangePasswordEndpoint.as_view(), name="forgot-password"),
    # path("set-password/", SetUserPasswordEndpoint.as_view(), name="set-password"),
]
