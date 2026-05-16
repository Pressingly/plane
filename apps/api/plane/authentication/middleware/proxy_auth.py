# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from uuid import uuid4

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError

from plane.authentication.middleware.proxy_auth_utils import (
    _coerce_bypass_paths,
    _is_bypass_path,
    _normalise_email,
)
from plane.authentication.utils.login import user_login
from plane.db.models import Profile, User, Workspace, WorkspaceMember
from plane.db.models.workspace import ROLE_CHOICES

# Build a label → value lookup so role names can be used symbolically.
# e.g. _ROLE["Member"] == 15, _ROLE["Guest"] == 5, _ROLE["Admin"] == 20
_ROLE = {label: value for value, label in ROLE_CHOICES}

# Security note: X-Auth-Request-* header spoofing is not a concern because the
# backend port is not exposed outside the internal Docker network. All traffic
# must pass through Traefik, which calls oauth2-proxy ForwardAuth and overwrites
# these headers before forwarding to the app. If the backend port is ever
# exposed directly (e.g. for debugging), remove it before deploying to
# production — a client with direct access could spoof X-Auth-Request-Email
# and impersonate any account.

_NEW_USER_FLAGS = {
    "is_password_autoset": True,
    "is_email_verified": True,
}


class ProxyAuthMiddleware:
    """
    Django middleware for mPass proxy authentication.

    oauth2-proxy sets X-Auth-Request-Email and X-Auth-Request-User on every
    request that has passed OIDC validation. This middleware reads those
    headers, finds or creates the corresponding Plane user, and establishes a
    native Django session — so the rest of the app sees a fully authenticated
    request.user just as it would after a normal login.

    To disable, remove this class from the MIDDLEWARE list in settings.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.bypass_paths = _coerce_bypass_paths(
            getattr(settings, "MPASS_BYPASS_PATHS", None)
        )

    def __call__(self, request):
        # Bypass paths use their own auth (god-mode local login, instance admin).
        # TODO(mpass): Keep OPTIONS bypass at the proxy layer; add an app-level
        # fallback here only if preflight routing becomes inconsistent.
        if _is_bypass_path(request.path, self.bypass_paths):
            return self.get_response(request)

        email = _normalise_email(self._read_proxy_email(request))

        if request.user.is_authenticated:
            # Short-circuit only when the upstream-asserted identity matches the
            # current Django session, or when no header is present (request did
            # not pass through ForwardAuth — header absence is not a logout signal).
            current = _normalise_email(request.user.email or "")
            if not email or current == email:
                return self.get_response(request)

            # Mismatch detected: proxy asserts a different identity than the
            # current session. Flush the stale session immediately so that if
            # subsequent re-auth fails (e.g., incoming user is inactive), the
            # request proceeds as unauthenticated rather than retaining the
            # previous user's identity.
            logout(request)

        if not email:
            return self.get_response(request)

        user = self._resolve_user(email)

        # Respect deactivated accounts — mPass authentication does not
        # override an explicit Plane account suspension.
        if not user.is_active:
            return self.get_response(request)

        user_login(request=request, user=user, is_app=True)
        return self.get_response(request)

    @staticmethod
    def _read_proxy_email(request):
        """Extract the upstream-asserted email from oauth2-proxy headers.

        Handles three cases:
          - X-Auth-Request-Email contains a real email → use as-is
          - X-Auth-Request-Email contains a bare username (user_id_claim=
            cognito:username) → synthesise <username>@DEFAULT_EMAIL_DOMAIN
          - X-Auth-Request-Email is empty but X-Auth-Request-User has a username
            → synthesise the same way

        Returns the raw (un-normalised) email string, or "" if none could be
        derived. Caller is responsible for `_normalise_email` before using.

        TODO(security): the bare-username synthesis paths let a Cognito
        principal whose username collides with a real Plane user's email
        local-part impersonate that user (e.g. `cognito:username=alice` →
        synthesised to `alice@askii.ai` → resolves to an existing `alice@askii.ai`
        Plane user). The defensive fix is to drop these synthesis paths and
        require a real email claim from the upstream proxy.
        """
        email = (request.META.get("HTTP_X_AUTH_REQUEST_EMAIL") or "").strip()
        if email and "@" not in email:
            domain = getattr(settings, "DEFAULT_EMAIL_DOMAIN", "askii.ai")
            email = f"{email}@{domain}"
        if not email:
            username = (request.META.get("HTTP_X_AUTH_REQUEST_USER") or "").strip()
            if username:
                domain = getattr(settings, "DEFAULT_EMAIL_DOMAIN", "askii.ai")
                email = f"{username}@{domain}"
        return email

    def _resolve_user(self, email):
        username_hint = email.split("@")[0] or uuid4().hex
        try:
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": username_hint,
                    "password": make_password(None),
                    **_NEW_USER_FLAGS,
                },
            )
        except IntegrityError:
            # Concurrent email insert race — fall back to get().
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise
            created = False

        if created:
            Profile.objects.get_or_create(user=user)

        # Run for every user (new or existing) — idempotent, no-op if already joined.
        self._auto_join_workspace(user)

        return user

    @staticmethod
    def _auto_join_workspace(user):
        """
        On every login, ensure the user is a member of the first existing workspace
        and that their onboarding is marked complete so Plane skips the wizard.
        If no workspace exists yet, do nothing — the normal create-workspace flow
        will be shown.
        Idempotent: get_or_create and conditional profile update make repeated
        calls safe and cheap.
        """

        # Prefer the workspace whose slug matches SMB_DEFAULT_WORKSPACE_NAME or SMB_NAME.
        smb_slug = getattr(settings, "SMB_DEFAULT_WORKSPACE_NAME", None) or getattr(
            settings, "SMB_NAME", ""
        )
        workspace = Workspace.objects.filter(slug=smb_slug).first()

        if workspace is None:
            return

        # Role: Member — auto-joined SSO users get full member access, not guest.
        WorkspaceMember.objects.get_or_create(
            workspace=workspace,
            member=user,
            defaults={"role": _ROLE["Member"], "is_active": True},
        )

        # Only update profile if onboarding is not yet complete — avoids a
        # write on every request for already-onboarded users.
        Profile.objects.filter(user=user, is_onboarded=False).update(
            is_onboarded=True,
            last_workspace_id=workspace.id,
            onboarding_step={
                "profile_complete": True,
                "workspace_create": True,
                "workspace_invite": True,
                "workspace_join": True,
            },
        )
