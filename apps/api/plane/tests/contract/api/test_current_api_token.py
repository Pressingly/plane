# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import pytest
from rest_framework import status

from plane.db.models import APIToken, User

CURRENT_TOKEN_URL = "/api/v1/users/me/api-tokens/current/"
USERS_ME_URL = "/api/v1/users/me/"


@pytest.fixture
def current_token(create_user):
    return APIToken.objects.create(user=create_user, label="current", token="current-token")


@pytest.fixture
def token_client(api_client, current_token):
    api_client.credentials(HTTP_X_API_KEY=current_token.token)
    return api_client


@pytest.fixture
def sibling_token(create_user):
    return APIToken.objects.create(user=create_user, label="sibling", token="sibling-token")


@pytest.fixture
def other_user_token(db):
    other_user = User.objects.create(email="other@plane.so", username="other_user")
    return APIToken.objects.create(user=other_user, label="other", token="other-user-token")


@pytest.mark.contract
@pytest.mark.django_db
class TestCurrentAPITokenRevoke:
    def test_deletes_the_token_used_for_the_request(self, token_client, current_token):
        response = token_client.delete(CURRENT_TOKEN_URL)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not APIToken.objects.filter(pk=current_token.pk).exists()
        assert APIToken.all_objects.get(pk=current_token.pk).deleted_at is not None

    def test_leaves_other_tokens_untouched(self, token_client, sibling_token, other_user_token):
        response = token_client.delete(CURRENT_TOKEN_URL)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert APIToken.objects.filter(pk=sibling_token.pk).exists()
        assert APIToken.objects.filter(pk=other_user_token.pk).exists()

    def test_revoked_token_stops_authenticating(self, token_client):
        token_client.delete(CURRENT_TOKEN_URL)

        assert token_client.delete(CURRENT_TOKEN_URL).status_code == status.HTTP_401_UNAUTHORIZED
        assert token_client.get(USERS_ME_URL).status_code == status.HTTP_403_FORBIDDEN

    def test_invalid_token_is_unauthorized(self, api_client, current_token):
        api_client.credentials(HTTP_X_API_KEY="not-a-real-token")

        response = api_client.delete(CURRENT_TOKEN_URL)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert APIToken.objects.filter(pk=current_token.pk).exists()

    def test_missing_token_is_unauthorized(self, api_client, current_token):
        response = api_client.delete(CURRENT_TOKEN_URL)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert APIToken.objects.filter(pk=current_token.pk).exists()

    def test_session_without_token_is_unauthorized(self, api_client, create_user, current_token):
        api_client.force_login(create_user)

        response = api_client.delete(CURRENT_TOKEN_URL)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert APIToken.objects.filter(pk=current_token.pk).exists()

    def test_only_delete_is_allowed(self, token_client):
        assert token_client.get(CURRENT_TOKEN_URL).status_code == status.HTTP_405_METHOD_NOT_ALLOWED
