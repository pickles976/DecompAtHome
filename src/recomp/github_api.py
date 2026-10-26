"""Bounded, dependency-free GitHub App authentication and REST transport."""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping

_API_VERSION = "2022-11-28"
_ACCEPT = "application/vnd.github+json"
_USER_AGENT = "recomp-coordinator/1"
_DEFAULT_MAX_BYTES = 1 << 20
_DEFAULT_PAGE_LIMIT = 100


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _compact_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


@dataclass(frozen=True)
class GitHubAppCredentials:
    app_id: int
    installation_id: int
    private_key: Path
    #: True only when the key arrived through systemd `LoadCredential=`.
    root_owned_credential: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.app_id, bool) or not isinstance(self.app_id, int) or self.app_id < 1:
            raise ValueError("GitHub App id must be a positive integer")
        if (isinstance(self.installation_id, bool)
                or self.installation_id < 1):
            raise ValueError("GitHub App installation id must be a positive integer")
        object.__setattr__(self, "private_key", Path(self.private_key))


def _key_is_acceptable(st_mode: int, st_uid: int, current_uid: int,
                       *, allow_root_owned: bool) -> str | None:
    """Return a reason the key is unacceptable, or None.

    `allow_root_owned` exists for systemd's `LoadCredential=`, which hands the
    service the key root-owned and readable only by the service user — mode
    0400 with an ACL on newer systemd, or 0440 where the per-user ACL is
    rendered as the group mask (systemd 255). That is stricter than the owner's
    own 0600 key, so accepting it does not weaken the rule; refusing it makes
    the documented service install impossible to run.
    """

    mode = stat.S_IMODE(st_mode)
    if not stat.S_ISREG(st_mode):
        return "GitHub App private key must be a regular file"
    if st_uid == current_uid:
        if mode & 0o077:
            return "GitHub App private key must not have group or other permissions"
        return None
    if allow_root_owned and st_uid == 0 and not (mode & ~0o550) and not (mode & 0o020):
        return None
    if mode & 0o077:
        return "GitHub App private key must not have group or other permissions"
    return "GitHub App private key must be owned by the current user"


def _validate_private_key(path: Path, *, allow_root_owned: bool = False) -> None:
    try:
        key_stat = os.stat(path)
    except OSError as exc:
        raise ValueError(f"cannot stat GitHub App private key: {path}") from exc
    reason = _key_is_acceptable(key_stat.st_mode, key_stat.st_uid, os.getuid(),
                                allow_root_owned=allow_root_owned)
    if reason is not None:
        raise ValueError(reason)


@dataclass(frozen=True)
class InstallationToken:
    value: str
    expires_at: float


def create_app_jwt(
    credentials: GitHubAppCredentials,
    *,
    clock: Callable[[], float] = time.time,
    runner: Callable[..., Any] = subprocess.run,
) -> str:
    """Create a ten-minute GitHub App JWT without exposing key bytes on argv."""

    _validate_private_key(credentials.private_key,
                          allow_root_owned=credentials.root_owned_credential)
    now = int(clock())
    header = _base64url(_compact_json({"alg": "RS256", "typ": "JWT"}))
    payload = _base64url(_compact_json({"iat": now - 30, "exp": now + 540, "iss": credentials.app_id}))
    signing_input = f"{header}.{payload}".encode("ascii")
    completed = runner(
        ["openssl", "dgst", "-sha256", "-sign", os.fspath(credentials.private_key)],
        input=signing_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    return f"{header}.{payload}.{_base64url(completed.stdout)}"


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _integer_header(headers: Mapping[str, str], name: str) -> int | None:
    value = _header(headers, name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _decode_body(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw.decode("utf-8", errors="replace")


def _read_bounded(response: Any, max_bytes: int) -> bytes:
    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise GitHubError(None, f"GitHub response body exceeds {max_bytes} bytes")
    return raw


class GitHubError(RuntimeError):
    """Sanitized GitHub failure with bounded response and rate-limit metadata."""

    def __init__(
        self,
        status: int | None,
        message: str,
        *,
        body: Any = None,
        rate_limit_remaining: int | None = None,
        rate_limit_reset: int | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.rate_limit_remaining = rate_limit_remaining
        self.rate_limit_reset = rate_limit_reset
        prefix = f"GitHub API status {status}: " if status is not None else "GitHub API: "
        super().__init__(prefix + message)


class InstallationTokenProvider:
    """Fetch and cache installation tokens until one minute before expiry."""

    def __init__(
        self,
        credentials: GitHubAppCredentials,
        *,
        base_url: str = "https://api.github.com",
        opener: Callable[..., Any] = urllib.request.urlopen,
        signer: Callable[[GitHubAppCredentials], str] = create_app_jwt,
        clock: Callable[[], float] = time.time,
        timeout: float = 30,
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ) -> None:
        self.credentials = credentials
        self.base_url = base_url.rstrip("/")
        self.opener = opener
        self.signer = signer
        self.clock = clock
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._cached: InstallationToken | None = None

    def token(self) -> str:
        now = self.clock()
        if self._cached is not None and now < self._cached.expires_at - 60:
            return self._cached.value
        request = urllib.request.Request(
            f"{self.base_url}/app/installations/{self.credentials.installation_id}/access_tokens",
            data=b"{}",
            method="POST",
            headers={
                "Accept": _ACCEPT,
                "Authorization": f"Bearer {self.signer(self.credentials)}",
                "X-GitHub-Api-Version": _API_VERSION,
                "User-Agent": _USER_AGENT,
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                raw = _read_bounded(response, self.max_bytes)
                status = getattr(response, "status", 200)
                headers = response.headers
        except urllib.error.HTTPError as exc:
            self._raise_http_error(exc, self.max_bytes)
        if status != 201 and status != 200:
            raise GitHubError(status, "installation token request failed", body=_decode_body(raw))
        payload = _decode_body(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get("token"), str):
            raise GitHubError(status, "installation token response is malformed")
        try:
            expires_at = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00")).timestamp()
        except (KeyError, AttributeError, TypeError, ValueError) as exc:
            raise GitHubError(status, "installation token expiry is malformed") from exc
        self._cached = InstallationToken(payload["token"], expires_at)
        return self._cached.value

    @staticmethod
    def _raise_http_error(exc: urllib.error.HTTPError, max_bytes: int) -> None:
        raw = exc.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise GitHubError(exc.code, f"GitHub response body exceeds {max_bytes} bytes") from None
        headers = exc.headers or {}
        raise GitHubError(
            exc.code,
            "installation token request failed",
            body=_decode_body(raw),
            rate_limit_remaining=_integer_header(headers, "X-RateLimit-Remaining"),
            rate_limit_reset=_integer_header(headers, "X-RateLimit-Reset"),
        ) from None


class GitHubClient:
    """Repository-scoped GitHub REST client with bounded, sanitized I/O."""

    def __init__(
        self,
        base_url: str,
        owner: str,
        repository: str,
        token_provider: Callable[[], str],
        *,
        opener: Callable[..., Any] = urllib.request.urlopen,
        viewer: tuple[int, str] | None = None,
        timeout: float = 30,
        page_limit: int = _DEFAULT_PAGE_LIMIT,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username is not None:
            raise ValueError("GitHub API base URL must be an absolute HTTP(S) origin")
        if not owner or "/" in owner or not repository or "/" in repository:
            raise ValueError("GitHub owner and repository must be non-empty path components")
        if page_limit < 1:
            raise ValueError("page_limit must be positive")
        self.base_url = base_url.rstrip("/")
        self._origin = (parsed.scheme.lower(), parsed.netloc.lower())
        self.owner = owner
        self.repository = repository
        self.token_provider = token_provider
        self.opener = opener
        self.timeout = timeout
        self.page_limit = page_limit
        self._viewer_cache: Any = None
        self._viewer_override = viewer

    @property
    def repo_path(self) -> str:
        return f"/repos/{self.owner}/{self.repository}"

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            raise ValueError("GitHub API path must begin with /")
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self._origin:
            raise GitHubError(None, "refusing GitHub URL outside configured API origin")
        return url

    def _request_with_headers(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        expected: Iterable[int] = (200,),
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ) -> tuple[Any, Mapping[str, str]]:
        url = self._url(path) if path.startswith("/") else self._validated_absolute_url(path)
        data = None if body is None else _compact_json(body)
        headers = {
            "Accept": _ACCEPT,
            "Authorization": f"Bearer {self.token_provider()}",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": _USER_AGENT,
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener(request, timeout=self.timeout) as response:
                raw = _read_bounded(response, max_bytes)
                status = getattr(response, "status", 200)
                response_headers = response.headers
        except urllib.error.HTTPError as exc:
            self._raise_http_error(exc, max_bytes)
        except GitHubError:
            raise
        except urllib.error.URLError as exc:
            raise GitHubError(None, f"request failed: {exc.reason}") from None
        if status not in tuple(expected):
            raise GitHubError(
                status,
                "unexpected response status",
                body=_decode_body(raw),
                rate_limit_remaining=_integer_header(response_headers, "X-RateLimit-Remaining"),
                rate_limit_reset=_integer_header(response_headers, "X-RateLimit-Reset"),
            )
        return _decode_body(raw), response_headers

    def _validated_absolute_url(self, url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self._origin:
            raise GitHubError(None, "refusing pagination link outside configured API origin")
        return url

    @staticmethod
    def _raise_http_error(exc: urllib.error.HTTPError, max_bytes: int) -> None:
        raw = exc.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise GitHubError(exc.code, f"GitHub response body exceeds {max_bytes} bytes") from None
        headers = exc.headers or {}
        body = _decode_body(raw)
        message = body.get("message", "request failed") if isinstance(body, dict) else "request failed"
        raise GitHubError(
            exc.code,
            str(message),
            body=body,
            rate_limit_remaining=_integer_header(headers, "X-RateLimit-Remaining"),
            rate_limit_reset=_integer_header(headers, "X-RateLimit-Reset"),
        ) from None

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        expected: Iterable[int] = (200,),
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ) -> Any:
        result, _headers = self._request_with_headers(
            method, path, body=body, expected=expected, max_bytes=max_bytes)
        return result

    def paginate(self, method: str, path: str, *, max_bytes: int = _DEFAULT_MAX_BYTES) -> Iterator[Any]:
        next_url = path
        visited: set[str] = set()
        for _page in range(self.page_limit):
            absolute = self._url(next_url) if next_url.startswith("/") else self._validated_absolute_url(next_url)
            if absolute in visited:
                raise GitHubError(None, "GitHub pagination loop detected")
            visited.add(absolute)
            payload, headers = self._request_with_headers(method, absolute, max_bytes=max_bytes)
            if not isinstance(payload, list):
                raise GitHubError(None, "paginated GitHub response must be a JSON array")
            yield from payload
            next_url = self._next_link(headers)
            if next_url is None:
                return
        raise GitHubError(None, f"GitHub pagination exceeded {self.page_limit} pages")

    def _next_link(self, headers: Mapping[str, str]) -> str | None:
        link_header = _header(headers, "Link")
        if not link_header:
            return None
        for item in link_header.split(","):
            sections = [part.strip() for part in item.split(";")]
            if len(sections) < 2 or not sections[0].startswith("<") or not sections[0].endswith(">"):
                continue
            relations = {part[4:].strip('"') for part in sections[1:] if part.startswith("rel=")}
            if "next" in relations:
                return self._validated_absolute_url(sections[0][1:-1])
        return None

    # Identity of whatever token is in use; trust guards must be able to ask it.
    # An installation token cannot call /user, so an App-authenticated client
    # is handed its identity (the App bot's user id and login) at construction.
    def _fetch_viewer(self) -> Any:
        if self._viewer_override is not None:
            return {"id": self._viewer_override[0], "login": self._viewer_override[1]}
        if self._viewer_cache is None:
            try:
                self._viewer_cache = self.request("GET", "/user")
            except GitHubError as exc:
                if exc.status == 403:
                    # The GitHub App's installation tokens cannot read /user, so
                    # a 403 here means a contributor pointed the CLI at App
                    # credentials. Say which credential the claim needs.
                    raise GitHubError(
                        exc.status,
                        "the token was rejected for this account; claims and "
                        "pull requests need the contributor's own credential "
                        "(`gh auth login`, or a fine-grained PAT with Issues "
                        "and Pull requests read/write on this repository "
                        "exported as GITHUB_TOKEN)",
                    ) from exc
                raise
        return self._viewer_cache

    @property
    def viewer_id(self) -> int:
        return int(self._fetch_viewer()["id"])

    @property
    def viewer_login(self) -> str:
        return str(self._fetch_viewer()["login"])

    # Issues and comments
    def list_issues(self) -> Iterator[Any]:
        return self.paginate("GET", f"{self.repo_path}/issues?state=all")

    def get_issue(self, number: int) -> Any:
        return self.request("GET", f"{self.repo_path}/issues/{number}")

    def create_issue(self, body: Mapping[str, Any]) -> Any:
        return self.request("POST", f"{self.repo_path}/issues", body=body, expected=(201,))

    def list_comments(self, issue_number: int) -> Iterator[Any]:
        return self.paginate("GET", f"{self.repo_path}/issues/{issue_number}/comments")

    def create_comment(self, issue_number: int, text: str) -> Any:
        return self.request("POST", f"{self.repo_path}/issues/{issue_number}/comments",
                            body={"body": text}, expected=(201,))

    def set_issue_labels(self, issue_number: int, labels: list[str]) -> Any:
        return self.request("POST", f"{self.repo_path}/issues/{issue_number}/labels",
                            body={"labels": labels})

    def update_issue(self, issue_number: int, body: Mapping[str, Any]) -> Any:
        return self.request("PATCH", f"{self.repo_path}/issues/{issue_number}", body=body)

    def list_labels(self) -> Iterator[Any]:
        return self.paginate("GET", f"{self.repo_path}/labels")

    def create_label(self, body: Mapping[str, Any]) -> Any:
        return self.request("POST", f"{self.repo_path}/labels", body=body, expected=(201,))

    # Pull requests and Git data
    def get_pull(self, number: int) -> Any:
        return self.request("GET", f"{self.repo_path}/pulls/{number}")

    def list_pulls(self, *, state: str = "open") -> Iterator[Any]:
        return self.paginate("GET", f"{self.repo_path}/pulls?state={state}")

    def create_pull(self, body: Mapping[str, Any]) -> Any:
        return self.request("POST", f"{self.repo_path}/pulls", body=body, expected=(201,))

    def list_pull_files(self, number: int) -> Iterator[Any]:
        return self.paginate("GET", f"{self.repo_path}/pulls/{number}/files")

    def get_tree(self, sha: str, *, recursive: bool = False) -> Any:
        suffix = "?recursive=1" if recursive else ""
        return self.request("GET", f"{self.repo_path}/git/trees/{sha}{suffix}")

    def get_blob(self, sha: str) -> Any:
        return self.request("GET", f"{self.repo_path}/git/blobs/{sha}")

    def get_ref(self, ref: str) -> Any:
        return self.request("GET", f"{self.repo_path}/git/ref/{ref}")

    def create_blob(self, body: Mapping[str, Any]) -> Any:
        return self.request("POST", f"{self.repo_path}/git/blobs", body=body, expected=(201,))

    def create_tree(self, body: Mapping[str, Any]) -> Any:
        return self.request("POST", f"{self.repo_path}/git/trees", body=body, expected=(201,))

    def create_commit(self, body: Mapping[str, Any]) -> Any:
        return self.request("POST", f"{self.repo_path}/git/commits", body=body, expected=(201,))

    def update_ref(self, ref: str, sha: str, *, force: bool = False) -> Any:
        return self.request("PATCH", f"{self.repo_path}/git/refs/{ref}",
                            body={"sha": sha, "force": force})

    # Checks and exact-head merge
    def create_check_run(self, body: Mapping[str, Any]) -> Any:
        return self.request("POST", f"{self.repo_path}/check-runs", body=body, expected=(201,))

    def update_check_run(self, check_run_id: int, body: Mapping[str, Any]) -> Any:
        return self.request("PATCH", f"{self.repo_path}/check-runs/{check_run_id}", body=body)

    def list_check_runs(self, head_sha: str) -> Iterator[Any]:
        payload = self.request(
            "GET", f"{self.repo_path}/commits/{head_sha}/check-runs?per_page=100")
        runs = payload.get("check_runs") if isinstance(payload, Mapping) else None
        return iter(runs if isinstance(runs, list) else [])

    def merge_pull(self, number: int, expected_head_sha: str, **body: Any) -> Any:
        return self.request(
            "PUT",
            f"{self.repo_path}/pulls/{number}/merge",
            body={**body, "expected_head_sha": expected_head_sha},
            expected=(200,),
        )
