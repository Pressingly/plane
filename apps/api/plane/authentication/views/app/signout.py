# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Standard library
from urllib.parse import urlparse

# Django imports
from django.views import View
from django.contrib.auth import logout
from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# Module imports
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
            # Always clear the Django session, even if user lookup/save failed
            logout(request)

        # If SSO (mPass) sign-out URL is configured, redirect there to also
        # clear the shared oauth2-proxy session and Cognito session.
        # Without this, the next request immediately re-authenticates the user
        # via Traefik ForwardAuth.
        mpass_signout_url = getattr(settings, "MPASS_SIGNOUT_URL", None)
        if mpass_signout_url:
            return HttpResponseRedirect(mpass_signout_url)

        return HttpResponseRedirect(base_host(request=request, is_app=True))

    def get(self, request):
        """
        Cross-origin redirect-chain entry-point for the foss-server-bundle
        portal's "Log out of all apps" flow.

        Clears the Django session via django.contrib.auth.logout(), then
        302s to ?next= (validated against PLATFORM_DOMAIN to prevent open
        redirect). The chain works because the browser is on this app's
        own domain when this endpoint runs — so Django's Set-Cookie scope
        is correct.

        CSRF-exempt (set at class level): no token is shared cross-origin
        with the portal. Residual risk is force-logout (attacker embeds
        <img src="…/sign-out"> ending the victim's session); low impact —
        only the session itself is lost, and re-auth via ForwardAuth is
        automatic.
        """
        logout(request)

        next_url = (request.GET.get("next") or "").strip()
        if next_url:
            if not self._is_allowed_next(next_url):
                return HttpResponseBadRequest(
                    "next= target host is not a subdomain of PLATFORM_DOMAIN"
                )
            return HttpResponseRedirect(next_url)

        # No ?next= — fall back to MPASS_SIGNOUT_URL so a manual hit still
        # chains through oauth2-proxy + Cognito.
        mpass_signout_url = getattr(settings, "MPASS_SIGNOUT_URL", None)
        if mpass_signout_url:
            return HttpResponseRedirect(mpass_signout_url)
        return HttpResponseRedirect(base_host(request=request, is_app=True))

    @staticmethod
    def _is_allowed_next(url):
        """True iff URL's host equals PLATFORM_DOMAIN or is a subdomain.

        Suffix match enforces a dot boundary: foss.arbisoft.com matches
        foss.arbisoft.com and *.foss.arbisoft.com but NOT
        foss.arbisoft.com.evil. Unset PLATFORM_DOMAIN → False (every
        ?next= rejected).
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
