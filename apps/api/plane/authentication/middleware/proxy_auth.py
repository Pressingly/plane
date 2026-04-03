# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import sys
from uuid import uuid4

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError

from plane.authentication.middleware.proxy_auth_utils import (
    _coerce_bypass_paths,
    _is_bypass_path,
    _normalise_email,
)
from plane.authentication.utils.login import user_login
from plane.db.models import Profile, User

# Security note: header spoofing is not a concern on protected routes because
# Traefik ForwardAuth overwrites X-Auth-Request-* headers before they reach
# the app. Bypass paths never run this middleware, so spoofed headers there
# have no effect either.

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
        # Layer 2 session already valid — nothing to do.
        # TODO(mpass): Remove this temporary debug log once the Traefik/oauth2-proxy
        # integration PRs are fully rolled out and verified in all environments.
        print(f"DEBUG >>>>>>>>>> middleware hit path={request.path} user={request.user}", file=sys.stderr, flush=True)
        if request.user.is_authenticated:
            return self.get_response(request)

        # Bypass paths use their own auth (god-mode local login, instance admin).
        # TODO(mpass): Keep OPTIONS bypass at the proxy layer; add an app-level
        # fallback here only if preflight routing becomes inconsistent.
        if _is_bypass_path(request.path, self.bypass_paths):
            return self.get_response(request)

        email = request.META.get("HTTP_X_AUTH_REQUEST_EMAIL")
        if not email:
            return self.get_response(request)

        email = _normalise_email(email)
        if not email:
            return self.get_response(request)

        user = self._resolve_user(email)

        # Respect deactivated accounts — mPass authentication does not
        # override an explicit Plane account suspension.
        if not user.is_active:
            return self.get_response(request)

        user_login(request=request, user=user, is_app=True)
        return self.get_response(request)

    def _resolve_user(self, email):
        try:
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": uuid4().hex,
                    "password": make_password(None),
                    **_NEW_USER_FLAGS,
                },
            )
        except IntegrityError:
            # A concurrent request raced us to the insert — fall back to get().
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise
            created = False

        if created:
            Profile.objects.get_or_create(user=user)

        return user
