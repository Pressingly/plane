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

        # Validate the redirect target against PLATFORM_DOMAIN.
        allowed_hosts = self._get_allowed_hosts_for_url(next_url)
        if not allowed_hosts:
            return HttpResponseBadRequest(
                "next= host is not a subdomain of PLATFORM_DOMAIN"
            )

        # Django's built-in open-redirect guard — CodeQL recognizes this as
        # a sanitizer when it directly guards a redirect in the same scope.
        if not url_has_allowed_host_and_scheme(
            next_url, allowed_hosts=allowed_hosts, require_https=False
        ):
            return HttpResponseBadRequest(
                "next= host is not a subdomain of PLATFORM_DOMAIN"
            )

        return HttpResponseRedirect(next_url)

    @staticmethod
    def _get_allowed_hosts_for_url(url):
        """Return allowed hosts set if *url*'s host is within PLATFORM_DOMAIN.

        Returns a set containing the URL's hostname (for use with
        url_has_allowed_host_and_scheme) if it passes dot-boundary domain
        validation; returns an empty set otherwise.
        """
        platform_domain = (
            getattr(settings, "PLATFORM_DOMAIN", "") or ""
        ).strip().lower().lstrip(".")
        if not platform_domain:
            return set()

        try:
            host = urlparse(url).hostname
        except ValueError:
            return set()
        if not host:
            return set()

        host = host.lower()
        # Dot-boundary enforcement: foss.arbisoft.com.evil does NOT match.
        if host == platform_domain or host.endswith("." + platform_domain):
            return {host}
        return set()
