# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
ForwardAuth middleware — trusts X-Auth-Request-Email / X-Auth-Request-User
headers set by an upstream proxy (e.g. oauth2-proxy, Authelia, Traefik
ForwardAuth) and transparently logs the user in, auto-provisioning their
account on first access.

SECURITY: only enable this behind a proxy that strips these headers from
untrusted clients. Never expose the API directly to the internet with this
middleware active.
"""

import logging
import uuid

from django.contrib.auth import login
from django.utils.deprecation import MiddlewareMixin

from plane.db.models import Profile, User

logger = logging.getLogger("plane.authentication.forward_auth")


class ForwardAuthMiddleware(MiddlewareMixin):
    """
    Processes X-Auth-Request-Email and X-Auth-Request-User headers injected
    by a trusted upstream ForwardAuth proxy.

    Behaviour per request:
      - Headers absent  → no-op, request continues normally.
      - User already authenticated in session → no-op.
      - User found by email → log them in via a new Django session.
      - User not found → auto-provision (create) the account, then log in.
    """

    EMAIL_HEADER = "HTTP_X_AUTH_REQUEST_EMAIL"
    USER_HEADER = "HTTP_X_AUTH_REQUEST_USER"

    def process_request(self, request):
        # Already authenticated — nothing to do.
        if hasattr(request, "user") and request.user.is_authenticated:
            return None

        email = self._extract_email(request)
        if not email:
            return None

        display_name = self._extract_display_name(request)

        try:
            user = self._get_or_provision(email, display_name)
        except Exception:
            logger.exception("ForwardAuth: failed to get or provision user for email=%s", email)
            return None

        try:
            login(request, user)
            logger.info("ForwardAuth: logged in user id=%s email=%s", user.id, user.email)
        except Exception:
            logger.exception("ForwardAuth: login() failed for user id=%s", user.id)

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_email(self, request):
        raw = request.META.get(self.EMAIL_HEADER, "").strip()
        return raw.lower() if raw else None

    def _extract_display_name(self, request):
        return request.META.get(self.USER_HEADER, "").strip()

    def _get_or_provision(self, email, display_name):
        user = User.objects.filter(email=email).first()
        if user:
            return user

        logger.info("ForwardAuth: provisioning new user for email=%s", email)
        user = User(
            email=email,
            username=uuid.uuid4().hex,
            is_email_verified=True,
            is_password_autoset=True,
        )
        # Set a random unusable-equivalent password so normal password auth is blocked.
        user.set_password(uuid.uuid4().hex)

        if display_name:
            # Use the proxy-supplied identifier as the display name.
            parts = display_name.split(None, 1)
            user.first_name = parts[0]
            user.last_name = parts[1] if len(parts) > 1 else ""

        user.save()

        # Profile is required by the app; create with defaults.
        Profile.objects.get_or_create(user=user)

        logger.info("ForwardAuth: provisioned user id=%s email=%s", user.id, email)
        return user
