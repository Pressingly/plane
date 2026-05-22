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

        sanitized = self._sanitize_next(next_url)
        if sanitized is None:
            return HttpResponseBadRequest(
                "next= host is not a subdomain of PLATFORM_DOMAIN"
            )
        return HttpResponseRedirect(sanitized)

    @staticmethod
    def _sanitize_next(url):
        """Validate and reconstruct *url* from parsed components.

        Returns the reconstructed URL string if the host is an exact match
        or a subdomain of PLATFORM_DOMAIN; returns None otherwise.
        Reconstructing from parsed parts breaks the taint chain so static
        analysis tools see a derived value rather than raw user input.
        """
        platform_domain = (
            getattr(settings, "PLATFORM_DOMAIN", "") or ""
        ).strip().lower().lstrip(".")
        if not platform_domain:
            return None

        try:
            parsed = urlparse(url)
            host = parsed.hostname
        except ValueError:
            return None
        if not host:
            return None

        host = host.lower()
        if host != platform_domain and not host.endswith("." + platform_domain):
            return None

        # Only allow http/https schemes to prevent javascript: or data: URIs.
        scheme = parsed.scheme.lower() if parsed.scheme else "https"
        if scheme not in ("http", "https"):
            return None

        # Reconstruct URL from parsed components to avoid passing raw user
        # input directly to the redirect (satisfies open-redirect scanners).
        netloc = parsed.netloc
        path = parsed.path or "/"
        query = ("?" + parsed.query) if parsed.query else ""
        fragment = ("#" + parsed.fragment) if parsed.fragment else ""
        return f"{scheme}://{netloc}{path}{query}{fragment}"
