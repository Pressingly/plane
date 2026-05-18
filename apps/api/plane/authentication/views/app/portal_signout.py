# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt


@method_decorator(csrf_exempt, name="dispatch")
class PortalSignOutEndpoint(View):
    """
    GET /auth/portal-sign-out/?next=<absolute_url>

    Clears the Django session and 302-redirects the browser to ``next``.

    Designed for the foss-server-bundle portal's "Log out of all apps"
    redirect chain — the portal can navigate the browser through each
    app's portal-sign-out URL, each step clearing its own session cookie
    while the browser is on that app's own domain (so the Set-Cookie
    scope is correct).

    CSRF-exempt: no token is shared cross-origin with the portal, so the
    POST + CSRF flow used by the in-app SignOutAuthEndpoint isn't usable
    here. The residual risk is force-logout (an attacker embeds
    ``<img src="…/portal-sign-out">`` and the victim's session ends).
    That's low impact (annoying, not destructive — the only state lost is
    the session itself, and re-auth via ForwardAuth is automatic).

    The ``next`` URL is validated against ``PLATFORM_DOMAIN`` (set by
    foss-server-bundle/platform.sh) to prevent this endpoint from being
    weaponised as an open redirect. The URL's host must equal
    ``PLATFORM_DOMAIN`` exactly or be a subdomain of it. Dot boundary
    enforced: ``foss.arbisoft.com`` matches subdomains but NOT
    ``foss.arbisoft.com.evil.example``.
    """

    def get(self, request):
        logout(request)

        next_url = (request.GET.get("next") or "").strip()

        if next_url:
            if not self._is_allowed_next(next_url):
                return HttpResponseBadRequest(
                    "next= target host is not a subdomain of PLATFORM_DOMAIN"
                )
            return HttpResponseRedirect(next_url)

        # No next= supplied — fall back to MPASS_SIGNOUT_URL so a manual hit
        # to this endpoint still chains through oauth2-proxy + Cognito.
        fallback = getattr(settings, "MPASS_SIGNOUT_URL", "") or "/"
        return HttpResponseRedirect(fallback)

    @staticmethod
    def _is_allowed_next(url):
        """True iff the URL's host equals PLATFORM_DOMAIN or is a subdomain.

        Suffix match enforces a dot boundary: ``foss.arbisoft.com``
        matches ``foss.arbisoft.com`` and ``*.foss.arbisoft.com``, but
        not ``foss.arbisoft.com.evil``. Unset PLATFORM_DOMAIN → False
        (every next= rejected).
        """
        platform_domain = (
            getattr(settings, "PLATFORM_DOMAIN", "") or ""
        ).strip().lower().lstrip(".")
        if not platform_domain:
            return False

        try:
            host = urlparse(url).hostname
        except ValueError:
            return False
        if not host:
            return False

        host = host.lower()
        return host == platform_domain or host.endswith("." + platform_domain)
