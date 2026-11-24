# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from datetime import timedelta
from uuid import uuid4

import pytest
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status

from plane.api.rate_limit import ApiKeyRateThrottle, ApiKeyRevocationRateThrottle
from plane.db.models import APIToken, Integration, User, WorkspaceIntegration

CURRENT_TOKEN_URL = "/api/v1/users/me/api-tokens/current/"
USERS_ME_URL = "/api/v1/users/me/"


def make_user():
    unique_id = uuid4().hex[:8]
    return User.objects.create(email=f"revoke-{unique_id}@plane.so", username=f"revoke_{unique_id}")


def make_token(user, **fields):
    return APIToken.objects.create(user=user, label="revoke-test", token=f"revoke-{uuid4().hex}", **fields)


def is_revoked(token):
    return (
        not APIToken.objects.filter(pk=token.pk).exists()
        and APIToken.all_objects.get(pk=token.pk).deleted_at is not None
    )


@pytest.fixture(autouse=True)
def reset_revocation_throttle():
    throttle = ApiKeyRevocationRateThrottle()
    cache.delete(throttle.cache_format % {"scope": throttle.scope, "ident": "127.0.0.1"})


@pytest.fixture
def owner(db):
    return make_user()


@pytest.fixture
def current_token(owner):
    return make_token(owner)


def revoke(api_client, token_value):
    api_client.credentials(HTTP_X_API_KEY=token_value)
    return api_client.delete(CURRENT_TOKEN_URL)


@pytest.mark.contract
@pytest.mark.django_db
class TestCurrentAPITokenRevoke:
    def test_deletes_the_token_used_for_the_request(self, api_client, current_token):
        response = revoke(api_client, current_token.token)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert is_revoked(current_token)

    def test_leaves_other_tokens_untouched(self, api_client, owner, current_token):
        sibling_token = make_token(owner)
        other_user_token = make_token(make_user())

        response = revoke(api_client, current_token.token)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert APIToken.objects.filter(pk=sibling_token.pk).exists()
        assert APIToken.objects.filter(pk=other_user_token.pk).exists()

    def test_revoked_token_stops_authenticating(self, api_client, current_token):
        revoke(api_client, current_token.token)

        response = revoke(api_client, current_token.token)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response["WWW-Authenticate"] == 'ApiKey realm="api"'
        assert api_client.get(USERS_ME_URL).status_code == status.HTTP_403_FORBIDDEN

    def test_expired_token_is_revoked(self, api_client, owner):
        token = make_token(owner, expired_at=timezone.now() - timedelta(days=1))

        assert revoke(api_client, token.token).status_code == status.HTTP_204_NO_CONTENT
        assert is_revoked(token)

    def test_inactive_token_is_revoked(self, api_client, owner):
        token = make_token(owner, is_active=False)

        assert revoke(api_client, token.token).status_code == status.HTTP_204_NO_CONTENT
        assert is_revoked(token)

    def test_token_of_deactivated_user_is_revoked(self, api_client, owner, current_token):
        owner.is_active = False
        owner.save()

        assert revoke(api_client, current_token.token).status_code == status.HTTP_204_NO_CONTENT
        assert is_revoked(current_token)

    def test_session_of_another_user_does_not_change_the_target(self, api_client, current_token):
        session_user = make_user()
        session_user_token = make_token(session_user)
        api_client.force_login(session_user)

        response = revoke(api_client, current_token.token)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert is_revoked(current_token)
        assert APIToken.objects.filter(pk=session_user_token.pk).exists()

    def test_exhausted_api_key_throttle_does_not_block_revocation(self, api_client, current_token):
        throttle = ApiKeyRateThrottle()
        cache.set(
            f"{throttle.scope}:{current_token.token}",
            [throttle.timer()] * (throttle.num_requests + 1),
            throttle.duration,
        )

        assert revoke(api_client, current_token.token).status_code == status.HTTP_204_NO_CONTENT
        assert is_revoked(current_token)

    def test_bot_token_is_not_revocable(self, api_client, owner):
        bot_token = make_token(owner, user_type=1)

        response = revoke(api_client, bot_token.token)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert APIToken.objects.filter(pk=bot_token.pk).exists()

    def test_token_used_by_an_integration_is_not_revocable(self, api_client, owner, current_token, workspace):
        integration = Integration.objects.create(title="Revoke test", provider=f"revoke-{uuid4().hex[:8]}")
        workspace_integration = WorkspaceIntegration.objects.create(
            workspace=workspace, actor=owner, integration=integration, api_token=current_token
        )

        response = revoke(api_client, current_token.token)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert APIToken.objects.filter(pk=current_token.pk).exists()
        assert WorkspaceIntegration.objects.filter(pk=workspace_integration.pk).exists()

    def test_unknown_token_is_unauthorized(self, api_client, current_token):
        response = revoke(api_client, f"revoke-{uuid4().hex}")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert APIToken.objects.filter(pk=current_token.pk).exists()

    def test_missing_token_is_unauthorized(self, api_client, current_token):
        response = api_client.delete(CURRENT_TOKEN_URL)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response["WWW-Authenticate"] == 'ApiKey realm="api"'
        assert APIToken.objects.filter(pk=current_token.pk).exists()

    def test_session_without_token_is_unauthorized(self, api_client, owner, current_token):
        api_client.force_login(owner)

        response = api_client.delete(CURRENT_TOKEN_URL)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert APIToken.objects.filter(pk=current_token.pk).exists()

    def test_only_delete_is_allowed(self, api_client, current_token):
        api_client.credentials(HTTP_X_API_KEY=current_token.token)

        assert api_client.get(CURRENT_TOKEN_URL).status_code == status.HTTP_405_METHOD_NOT_ALLOWED
