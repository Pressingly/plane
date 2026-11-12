# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import hmac

from plane.authentication.middleware.config_values import configured

EDGE_SECRET_HEADER = "HTTP_X_MPASS_EDGE_SECRET"
MIN_EDGE_SECRET_LENGTH = 32


def edge_secret_is_usable(secret: str) -> bool:
    """A CHANGE_ME_ placeholder counts as unset at any length, so it trusts nothing."""
    return len(configured(secret)) >= MIN_EDGE_SECRET_LENGTH


def request_is_from_edge(request, secret: str) -> bool:
    """True only when the request carries the secret Traefik injects on the SSO router.

    An unusable secret trusts nothing: identity headers must then be ignored,
    because without the secret a direct call on the backend network is
    indistinguishable from one that passed mPass ForwardAuth.
    """
    if not edge_secret_is_usable(secret):
        return False
    presented = request.META.get(EDGE_SECRET_HEADER, "")
    return hmac.compare_digest(secret.encode(), presented.encode())
