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

        if not self._is_allowed_next(next_url):
            return HttpResponseBadRequest(
                "next= host is not a subdomain of PLATFORM_DOMAIN"
            )
        return HttpResponseRedirect(next_url)

    @staticmethod
    def _is_allowed_next(url):
        # Suffix match enforces a dot boundary so foss.arbisoft.com.evil
        # does NOT match the foss.arbisoft.com PLATFORM_DOMAIN.
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
