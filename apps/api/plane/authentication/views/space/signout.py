# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.views import View
from django.contrib.auth import logout
from django.conf import settings
from django.http import HttpResponseRedirect
from django.utils import timezone

# Module imports
from plane.authentication.utils.host import base_host, user_ip
from plane.db.models import User
from plane.utils.path_validator import get_safe_redirect_url


class SignOutAuthSpaceEndpoint(View):
    def post(self, request):
        next_path = request.POST.get("next_path")

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

        url = get_safe_redirect_url(base_url=base_host(request=request, is_space=True), next_path=next_path)
        return HttpResponseRedirect(url)
