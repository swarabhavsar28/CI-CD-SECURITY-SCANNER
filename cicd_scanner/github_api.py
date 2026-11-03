"""Thin GitHub REST client used for fetching workflows and release metadata."""

from __future__ import annotations

import os
from typing import Any

import requests

API_ROOT = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


def resolve_token(explicit: str | None = None) -> str | None:
    return explicit or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


def github_get(
    path_or_url: str,
    token: str | None = None,
    *,
    accept: str = "application/vnd.github+json",
    params: dict[str, Any] | None = None,
    timeout: float = 15,
) -> requests.Response:
    url = path_or_url if path_or_url.startswith("http") else f"{API_ROOT}{path_or_url}"
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "cicd-scanner"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
    except requests.RequestException as exc:
        raise GitHubError(f"network error talking to GitHub: {exc}") from exc

    if response.status_code == 401:
        raise GitHubError("GitHub rejected the token (401 Unauthorized)")
    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        raise GitHubError(
            "GitHub API rate limit exceeded; pass --token (or set GITHUB_TOKEN) to raise the limit"
        )
    if response.status_code == 404:
        raise GitHubError(f"GitHub returned 404 for {url}")
    if response.status_code >= 400:
        raise GitHubError(f"GitHub returned HTTP {response.status_code} for {url}")
    return response
