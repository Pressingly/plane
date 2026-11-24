# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Third party imports
from rest_framework import status
from rest_framework.response import Response
from drf_spectacular.utils import OpenApiResponse

# Module imports
from plane.api.serializers import UserLiteSerializer
from plane.api.middleware.api_authentication import APIKeyAuthentication
from plane.api.views.base import BaseAPIView
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


class CurrentAPITokenAuthentication(APIKeyAuthentication):
    def authenticate_header(self, request):
        return self.auth_header_name


class CurrentAPITokenEndpoint(BaseAPIView):
    authentication_classes = [CurrentAPITokenAuthentication]
    model = APIToken

    @user_docs(
        operation_id="revoke_current_api_token",
        summary="Revoke current API token",
        description="Delete the API token that authenticated this request. Other tokens are left untouched.",
        responses={204: DELETED_RESPONSE},
    )
    def delete(self, request):
        APIToken.objects.get(token=request.auth, user=request.user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
