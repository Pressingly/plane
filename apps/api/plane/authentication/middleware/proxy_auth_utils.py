# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import re

_DEFAULT_BYPASS_PATHS = ["/god-mode", "/api/instances"]
_PROJECT_IDENTIFIER_MAX_LENGTH = 10


def _normalise_email(email: str) -> str:
    return email.strip().lower()


def _is_bypass_path(path: str, bypass_paths: list) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in bypass_paths)


def _coerce_bypass_paths(setting) -> list:
    if not setting:
        return list(_DEFAULT_BYPASS_PATHS)
    if isinstance(setting, str):
        paths = [p.strip() for p in setting.split(",") if p.strip()]
        return paths if paths else list(_DEFAULT_BYPASS_PATHS)
    return list(setting)


def _smb_project_identifier(smb_name) -> str:
    return re.sub(r"[^A-Z0-9]", "", (smb_name or "").upper())[:_PROJECT_IDENTIFIER_MAX_LENGTH]
