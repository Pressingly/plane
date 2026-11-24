# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.db import transaction
from django.utils import timezone

# Third party imports
from rest_framework import status
from rest_framework.response import Response
from drf_spectacular.utils import OpenApiResponse

# Module imports
from plane.api.serializers import UserLiteSerializer
from plane.api.middleware.api_authentication import APIKeyAuthentication
from plane.api.rate_limit import ApiKeyRevocationRateThrottle
from plane.api.views.base import BaseAPIView
from plane.bgtasks.deletion_task import soft_delete_related_objects
from plane.db.models import APIToken, User
from plane.utils.openapi.decorators import user_docs
from plane.utils.openapi import DELETED_RESPONSE, USER_EXAMPLE


class UserEndpoint(BaseAPIView):
    serializer_class = UserLiteSerializer
    model = User

    @user_docs(
        operation_id="get_current_user",
        summary="Get current user",
        description="Retrieve the authenticated user's profile information including basic details.",
        responses={
            200: OpenApiResponse(
                description="Current user profile",
                response=UserLiteSerializer,
                examples=[USER_EXAMPLE],
            ),
        },
    )
    def get(self, request):
        """Get current user

        Retrieve the authenticated user's profile information including basic details.
        Returns user data based on the current authentication context.
        """
        serializer = UserLiteSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CurrentAPITokenEndpoint(BaseAPIView):
    authentication_classes = []
    permission_classes = []
    model = APIToken

    def get_throttles(self):
        return [ApiKeyRevocationRateThrottle()]

    @user_docs(
        operation_id="revoke_current_api_token",
        summary="Revoke current API token",
        description=(
            "Soft-delete the API token sent in the X-API-Key header. Holding the key is enough: expired or "
            "inactive tokens and tokens of deactivated users are revoked too. Other tokens are never touched. "
            "Unlike other v1 routes, a missing, unknown or already revoked key returns 401, not 403."
        ),
        auth=[{"ApiKeyAuthentication": []}],
        responses={204: DELETED_RESPONSE},
    )
    def delete(self, request):
        api_key = request.headers.get(APIKeyAuthentication.auth_header_name)
        if not api_key or not revoke_api_token(api_key):
            return Response(
                {"error": "Given API token is not valid"},
                status=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": 'ApiKey realm="api"'},
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


def revoke_api_token(api_key):
    token = APIToken.objects.filter(token=api_key).first()
    if token is None:
        return False
    with transaction.atomic():
        revoked = APIToken.objects.filter(pk=token.pk).update(deleted_at=timezone.now())
        if revoked:
            soft_delete_related_objects(APIToken._meta.app_label, APIToken._meta.model_name, token.pk)
    return bool(revoked)
