# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from urllib.parse import urlparse

from django.views import View
from django.contrib.auth import logout
from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt

from plane.authentication.utils.host import user_ip, base_host
from plane.db.models import User


@method_decorator(csrf_exempt, name="dispatch")
class SignOutAuthEndpoint(View):
    def post(self, request):
        try:
            user = User.objects.get(pk=request.user.id)
            user.last_logout_ip = user_ip(request=request)
            user.last_logout_time = timezone.now()
            user.save()
        except Exception:
            pass
        finally:
            logout(request)

        mpass_signout_url = getattr(settings, "MPASS_SIGNOUT_URL", None)
        if mpass_signout_url:
            return HttpResponseRedirect(mpass_signout_url)
        return HttpResponseRedirect(base_host(request=request, is_app=True))

    def get(self, request):
        # Delegate to POST so last_logout_ip/_time get tracked and the
        # session is flushed the same way. Only override the redirect
        # target if ?next= was passed (portal logout-chain hop).
        response = self.post(request)

        next_url = (request.GET.get("next") or "").strip()
        if not next_url:
            return response

        redirect_url = self._validated_redirect_url(next_url)
        if redirect_url is None:
            return HttpResponseBadRequest(
                "next= host is not a subdomain of PLATFORM_DOMAIN"
            )
        return HttpResponseRedirect(redirect_url)

    @staticmethod
    def _validated_redirect_url(url):
        """Validate *url* against the PLATFORM_DOMAIN allowlist.

        Returns a safe, server-derived redirect URL string if the host is an
        exact match or a subdomain of PLATFORM_DOMAIN; returns None otherwise.
        """
        platform_domain = (
            getattr(settings, "PLATFORM_DOMAIN", "") or ""
        ).strip().lower().lstrip(".")
        if not platform_domain:
            return None

        # Build the set of allowed hosts: the platform domain itself plus
        # wildcard subdomains (e.g. "foss.arbisoft.com" allows
        # "docs.foss.arbisoft.com").
        try:
            parsed = urlparse(url)
            host = parsed.hostname
        except ValueError:
            return None
        if not host:
            return None

        host = host.lower()
        # Dot-boundary enforcement: foss.arbisoft.com.evil does NOT match.
        if host != platform_domain and not host.endswith("." + platform_domain):
            return None

        # Use Django's built-in redirect-URL validator as the authoritative
        # safety check (recognized by CodeQL as a sanitizer). Pass the
        # already-validated host as the allowed host for exact matching.
        if not url_has_allowed_host_and_scheme(
            url, allowed_hosts={host}, require_https=False
        ):
            return None

        # Reconstruct from parsed components so the redirect target is a
        # server-derived literal rather than the raw request parameter.
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc
        path = parsed.path or "/"
        query = ("?" + parsed.query) if parsed.query else ""
        fragment = ("#" + parsed.fragment) if parsed.fragment else ""
        return f"{scheme}://{netloc}{path}{query}{fragment}"
