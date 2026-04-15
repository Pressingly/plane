/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import type { ReactNode } from "react";
import { observer } from "mobx-react";
import { useSearchParams } from "next/navigation";
import useSWR from "swr";
// components
import { LogoSpinner } from "@/components/common/logo-spinner";
import { buildOAuth2SignInUrl } from "@/lib/oauth2-proxy";
// helpers
import { EPageTypes } from "@/helpers/authentication.helper";
// hooks
import { useWorkspace } from "@/hooks/store/use-workspace";
import { useUser, useUserProfile, useUserSettings } from "@/hooks/store/user";
import { useAppRouter } from "@/hooks/use-app-router";

type TPageType = EPageTypes;

type TAuthenticationWrapper = {
  children: ReactNode;
  pageType?: TPageType;
};

const isSafeRelativePath = (path: string): boolean => {
  if (!path.startsWith("/")) return false;
  if (path.startsWith("//")) return false;
  if (/^[a-z][a-z0-9+.-]*:/i.test(path)) return false;
  return true;
};

export const AuthenticationWrapper = observer(function AuthenticationWrapper(props: TAuthenticationWrapper) {
  const router = useAppRouter();
  const searchParams = useSearchParams();
  const nextPath = searchParams.get("next_path");
  // props
  const { children, pageType = EPageTypes.AUTHENTICATED } = props;
  // hooks
  const { isLoading: isUserLoading, data: currentUser, fetchCurrentUser } = useUser();
  const { data: currentUserProfile } = useUserProfile();
  const { data: currentUserSettings } = useUserSettings();
  const { loader: workspacesLoader, workspaces } = useWorkspace();

  const { isLoading: isUserSWRLoading } = useSWR("USER_INFORMATION", async () => await fetchCurrentUser(), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  });

  const isUserOnboard =
    currentUserProfile?.is_onboarded ||
    (currentUserProfile?.onboarding_step?.profile_complete &&
      currentUserProfile?.onboarding_step?.workspace_create &&
      currentUserProfile?.onboarding_step?.workspace_invite &&
      currentUserProfile?.onboarding_step?.workspace_join) ||
    false;

  const getWorkspaceRedirectionUrl = (): string => {
    let redirectionRoute = "/create-workspace";

    // Allow only safe relative paths to avoid external or scheme-based redirects.
    if (nextPath && isSafeRelativePath(nextPath.toString())) {
      redirectionRoute = nextPath.toString();
      return redirectionRoute;
    }

    // validate the last and fallback workspace_slug
    const currentWorkspaceSlug =
      currentUserSettings?.workspace?.last_workspace_slug || currentUserSettings?.workspace?.fallback_workspace_slug;

    // validate the current workspace_slug is available in the user's workspace list
    const isCurrentWorkspaceValid = Object.values(workspaces || {}).findIndex(
      (workspace) => workspace.slug === currentWorkspaceSlug
    );

    if (isCurrentWorkspaceValid >= 0) redirectionRoute = `/${currentWorkspaceSlug}`;

    return redirectionRoute;
  };

  if ((isUserSWRLoading || isUserLoading || workspacesLoader) && !currentUser?.id)
    return (
      <div className="relative flex h-screen w-full items-center justify-center">
        <LogoSpinner />
      </div>
    );

  if (pageType === EPageTypes.PUBLIC) return <>{children}</>;

  if (pageType === EPageTypes.NON_AUTHENTICATED) {
    if (!currentUser?.id) {
      if (typeof window !== "undefined" && import.meta.env.VITE_OAUTH2_PROXY_BASE_PATH) {
        window.location.href = buildOAuth2SignInUrl(window.location.href);
        return <></>;
      }
      return <>{children}</>;
    } else {
      if (currentUserProfile?.id && isUserOnboard) {
        const currentRedirectRoute = getWorkspaceRedirectionUrl();
        router.push(currentRedirectRoute);
        return <></>;
      } else {
        router.push("/onboarding");
        return <></>;
      }
    }
  }

  if (pageType === EPageTypes.ONBOARDING) {
    if (!currentUser?.id) {
      if (typeof window !== "undefined" && import.meta.env.VITE_OAUTH2_PROXY_BASE_PATH) {
        window.location.href = buildOAuth2SignInUrl(window.location.href);
        return <></>;
      }
      router.push("/");
      return <></>;
    } else {
      if (currentUser && currentUserProfile?.id && isUserOnboard) {
        const currentRedirectRoute = getWorkspaceRedirectionUrl();
        router.replace(currentRedirectRoute);
        return <></>;
      } else return <>{children}</>;
    }
  }

  if (pageType === EPageTypes.SET_PASSWORD) {
    if (!currentUser?.id) {
      if (typeof window !== "undefined" && import.meta.env.VITE_OAUTH2_PROXY_BASE_PATH) {
        window.location.href = buildOAuth2SignInUrl(window.location.href);
        return <></>;
      }
      router.push("/");
      return <></>;
    } else {
      if (currentUser && !currentUser?.is_password_autoset && currentUserProfile?.id && isUserOnboard) {
        const currentRedirectRoute = getWorkspaceRedirectionUrl();
        router.push(currentRedirectRoute);
        return <></>;
      } else return <>{children}</>;
    }
  }

  if (pageType === EPageTypes.AUTHENTICATED) {
    if (currentUser?.id) {
      if (currentUserProfile && currentUserProfile?.id && isUserOnboard) return <>{children}</>;
      else {
        router.push(`/onboarding`);
        return <></>;
      }
    } else {
      if (typeof window !== "undefined" && import.meta.env.VITE_OAUTH2_PROXY_BASE_PATH) {
        window.location.href = buildOAuth2SignInUrl(window.location.href);
        return <></>;
      }
      router.push("/");
      return <></>;
    }
  }

  return <>{children}</>;
});
