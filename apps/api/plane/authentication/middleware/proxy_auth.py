# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from uuid import uuid4

from django.conf import settings
from django.contrib.auth import logout as django_logout
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError

from plane.authentication.middleware.proxy_auth_utils import (
    _coerce_bypass_paths,
    _is_bypass_path,
    _normalise_email,
)
from plane.authentication.utils.login import user_login
from plane.db.models import Profile, User

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
        # Skipped before any session/header inspection so admin tooling stays
        # untouched even if a stale Django session is present.
        if _is_bypass_path(request.path, self.bypass_paths):
            return self.get_response(request)

        header_email = self._extract_header_email(request)

        if request.user.is_authenticated:
            session_email = _normalise_email(getattr(request.user, "email", "") or "")
            if not header_email or header_email == session_email:
                # Session matches the upstream-asserted identity (or no header
                # to compare against) — pass through.
                return self.get_response(request)
            # Header asserts a different identity than the Django session.
            # Drop the stale session before re-resolving so the next request
            # carries cookies for the real upstream user. Without this, a
            # browser whose Cognito session has been swapped out continues to
            # serve the previous user's data until SESSION_COOKIE_AGE expires.
            django_logout(request)

        if not header_email:
            return self.get_response(request)

        user = self._resolve_user(header_email)

        # Respect deactivated accounts — mPass authentication does not
        # override an explicit Plane account suspension.
        if not user.is_active:
            return self.get_response(request)

        user_login(request=request, user=user, is_app=True)
        return self.get_response(request)

    def _extract_header_email(self, request):
        email = (request.META.get("HTTP_X_AUTH_REQUEST_EMAIL") or "").strip()
        if email and "@" not in email:
            # Header holds a bare username (user_id_claim=cognito:username). Synth email.
            domain = getattr(settings, "DEFAULT_EMAIL_DOMAIN", "askii.ai")
            email = f"{email}@{domain}"
        if not email:
            username = (request.META.get("HTTP_X_AUTH_REQUEST_USER") or "").strip()
            if username:
                domain = getattr(settings, "DEFAULT_EMAIL_DOMAIN", "askii.ai")
                email = f"{username}@{domain}"
        return _normalise_email(email) if email else ""

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
            # IntegrityError can fire on either unique constraint:
            # 1. email — concurrent insert race, the row now exists.
            # 2. username — a different email already holds username_hint
            #    (e.g. alice@a.com vs alice@b.com from federated pools).
            # Look up by email first; if missing, retry with a uuid-based
            # username so the second user isn't permanently locked out.
            try:
                user = User.objects.get(email=email)
                created = False
            except User.DoesNotExist:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "username": uuid4().hex,
                        "password": make_password(None),
                        **_NEW_USER_FLAGS,
                    },
                )

        if created:
            Profile.objects.get_or_create(user=user)

        return user
