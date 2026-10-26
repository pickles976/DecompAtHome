from __future__ import annotations

import base64
import io
import json
import os
import stat
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from recomp.github_api import (
    GitHubAppCredentials,
    GitHubClient,
    GitHubError,
    InstallationTokenProvider,
    _key_is_acceptable,
    create_app_jwt,
)


class FakeResponse:
    def __init__(self, payload, *, status=200, headers=None):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        return self.payload if size < 0 else self.payload[:size]


class FakeOpener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requested_urls = []
        self.requests = []
        self.installation_requests = 0

    def __call__(self, request, timeout=30):
        self.requests.append(request)
        self.requested_urls.append(request.full_url)
        if request.full_url.endswith("/access_tokens"):
            self.installation_requests += 1
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _expiry(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def test_installation_tokens_are_cached_until_one_minute_before_expiry(tmp_path):
    fake_opener = FakeOpener(FakeResponse({"token": "installation-token", "expires_at": _expiry(2000)}))
    creds = GitHubAppCredentials(12, 34, tmp_path / "app.pem")
    provider = InstallationTokenProvider(
        creds,
        base_url="https://api.github.test",
        opener=fake_opener,
        signer=lambda _: "jwt",
        clock=lambda: 1000,
    )
    first = provider.token()
    second = provider.token()
    assert first == second == "installation-token"
    assert fake_opener.installation_requests == 1
    request = fake_opener.requests[0]
    assert request.get_method() == "POST"
    assert request.headers["Authorization"] == "Bearer jwt"


def test_installation_token_refreshes_during_last_minute(tmp_path):
    now = [1000]
    opener = FakeOpener(
        FakeResponse({"token": "first", "expires_at": _expiry(1100)}),
        FakeResponse({"token": "second", "expires_at": _expiry(2100)}),
    )
    provider = InstallationTokenProvider(
        GitHubAppCredentials(12, 34, tmp_path / "app.pem"),
        opener=opener,
        signer=lambda _: "jwt",
        clock=lambda: now[0],
    )
    assert provider.token() == "first"
    now[0] = 1040
    assert provider.token() == "second"
    assert opener.installation_requests == 2


def test_app_jwt_uses_canonical_claims_and_never_passes_secret_on_argv(tmp_path):
    key = tmp_path / "app.pem"
    key.write_text("secret-key-material")
    key.chmod(0o600)
    seen = {}

    @dataclass
    class Result:
        stdout: bytes = b"signature"
        stderr: bytes = b""

    def runner(argv, **kwargs):
        seen.update(argv=argv, kwargs=kwargs)
        return Result()

    token = create_app_jwt(GitHubAppCredentials(12, 34, key), clock=lambda: 1000, runner=runner)
    header, payload, signature = token.split(".")
    decode = lambda value: json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
    assert decode(header) == {"alg": "RS256", "typ": "JWT"}
    assert decode(payload) == {"exp": 1540, "iat": 970, "iss": 12}
    assert signature == base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
    assert seen["argv"] == ["openssl", "dgst", "-sha256", "-sign", os.fspath(key)]
    assert b"secret-key-material" not in seen["kwargs"]["input"]
    assert seen["kwargs"]["env"] == {"PATH": os.environ.get("PATH", "")}


def test_app_key_must_be_owned_by_current_user_and_private(tmp_path, monkeypatch):
    key = tmp_path / "app.pem"
    key.write_text("key")
    key.chmod(0o640)
    with pytest.raises(ValueError, match="group or other permissions"):
        create_app_jwt(GitHubAppCredentials(1, 2, key))
    key.chmod(0o600)
    real_stat = key.stat()
    monkeypatch.setattr(
        "recomp.github_api.os.stat",
        lambda _path: os.stat_result((real_stat.st_mode, real_stat.st_ino, real_stat.st_dev,
                                      real_stat.st_nlink, os.getuid() + 1, real_stat.st_gid,
                                      real_stat.st_size, real_stat.st_atime,
                                      real_stat.st_mtime, real_stat.st_ctime)),
    )
    with pytest.raises(ValueError, match="current user"):
        create_app_jwt(GitHubAppCredentials(1, 2, key))


def test_a_systemd_credential_key_is_accepted_only_when_root_owned_and_read_only():
    """`LoadCredential=` delivers a root-owned file readable only by the service."""

    def verdict(mode, uid, *, allow_root_owned):
        return _key_is_acceptable(stat.S_IFREG | mode, uid, 1000,
                                  allow_root_owned=allow_root_owned)

    assert verdict(0o400, 0, allow_root_owned=True) is None
    assert verdict(0o500, 0, allow_root_owned=True) is None
    # systemd 255 renders the per-user ACL as a group-readable mask (0440);
    # refusing it would break the documented LoadCredential install.
    assert verdict(0o440, 0, allow_root_owned=True) is None
    assert verdict(0o550, 0, allow_root_owned=True) is None
    assert verdict(0o460, 0, allow_root_owned=True) is not None
    assert verdict(0o444, 0, allow_root_owned=True) is not None
    assert verdict(0o600, 0, allow_root_owned=True) is not None
    assert verdict(0o440, 0, allow_root_owned=False) is not None
    assert verdict(0o400, 42, allow_root_owned=True) is not None
    assert verdict(0o400, 0, allow_root_owned=False) is not None
    assert verdict(0o600, 1000, allow_root_owned=False) is None
    assert verdict(0o400, 1000, allow_root_owned=False) is None
    assert _key_is_acceptable(stat.S_IFDIR | 0o500, 0, 1000,
                              allow_root_owned=True) is not None


def test_viewer_identity_is_fetched_once_and_cached():
    opener = FakeOpener(FakeResponse({"id": 348113819, "login": "sage-recomp[bot]"}))
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token",
                          opener=opener)
    assert client.viewer_id == 348113819
    assert client.viewer_login == "sage-recomp[bot]"
    assert client.viewer_id == 348113819
    assert len(opener.requests) == 1


def test_app_authenticated_client_uses_the_supplied_viewer_identity():
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token",
                          opener=FakeOpener(), viewer=(348113819, "sage-recomp[bot]"))
    assert client.viewer_id == 348113819
    assert client.viewer_login == "sage-recomp[bot]"
    assert client._viewer_cache is None



def test_a_rejected_viewer_token_names_the_credential_a_claim_needs():
    """App installation tokens cannot read /user; a contributor hitting that
    403 must be told which credential to use, not handed a bare API status."""
    error = urllib.error.HTTPError("https://api.github.test/user", 403,
                                   "Resource not accessible by integration",
                                   {}, io.BytesIO(b'{"message":"nope"}'))
    client = GitHubClient("https://api.github.test", "acme", "game",
                          lambda: "ghs_installation", opener=FakeOpener(error))
    with pytest.raises(GitHubError) as caught:
        client.viewer_id
    message = str(caught.value)
    assert "gh auth login" in message and "GITHUB_TOKEN" in message
    assert "ghs_installation" not in message


def test_paginate_follows_only_same_origin_next_links():
    opener = FakeOpener(
        FakeResponse([{"id": 1}], headers={"Link": '<https://api.github.test/repos/acme/game/issues?page=2>; rel="next"'}),
        FakeResponse([{"id": 2}]),
    )
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token", opener=opener)
    assert [row["id"] for row in client.paginate("GET", "/repos/acme/game/issues")] == [1, 2]
    assert opener.requested_urls == [
        "https://api.github.test/repos/acme/game/issues",
        "https://api.github.test/repos/acme/game/issues?page=2",
    ]


def test_paginate_rejects_cross_origin_links():
    opener = FakeOpener(FakeResponse([], headers={"Link": '<https://evil.test/steal>; rel="next"'}))
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token", opener=opener)
    with pytest.raises(GitHubError, match="origin"):
        list(client.paginate("GET", "/repos/acme/game/issues"))
    assert opener.requested_urls == ["https://api.github.test/repos/acme/game/issues"]


@pytest.mark.parametrize("status", [401, 403, 422])
def test_errors_include_bounded_body_and_rate_limit_without_leaking_token(status):
    token = "super-secret-token"
    url = "https://api.github.test/repos/acme/game/issues"
    error = urllib.error.HTTPError(
        url,
        status,
        "failure",
        {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1234"},
        io.BytesIO(b'{"message":"denied"}'),
    )
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: token, opener=FakeOpener(error))
    with pytest.raises(GitHubError) as caught:
        client.request("GET", "/repos/acme/game/issues")
    assert caught.value.status == status
    assert caught.value.body == {"message": "denied"}
    assert caught.value.rate_limit_remaining == 0
    assert caught.value.rate_limit_reset == 1234
    assert token not in str(caught.value)


def test_response_body_is_capped():
    client = GitHubClient(
        "https://api.github.test", "acme", "game", lambda: "token",
        opener=FakeOpener(FakeResponse(b"x" * 9)),
    )
    with pytest.raises(GitHubError, match="response body exceeds 8 bytes"):
        client.request("GET", "/repos/acme/game/issues", max_bytes=8)


def test_request_sets_fixed_headers_and_encodes_json():
    opener = FakeOpener(FakeResponse({"id": 7}, status=201))
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token", opener=opener)
    assert client.request("POST", "/repos/acme/game/issues", body={"title": "Task"}, expected=(201,)) == {"id": 7}
    request = opener.requests[0]
    assert request.headers["Accept"] == "application/vnd.github+json"
    assert request.headers["Authorization"] == "Bearer token"
    assert request.headers["X-github-api-version"] == "2022-11-28"
    assert request.headers["User-agent"] == "recomp-coordinator/1"
    assert json.loads(request.data) == {"title": "Task"}


def test_typed_helpers_are_thin_repository_scoped_wrappers():
    class SpyClient(GitHubClient):
        def __init__(self):
            super().__init__("https://api.github.test", "acme", "game", lambda: "token")
            self.calls = []

        def request(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            return {"ok": True}

        def paginate(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            return iter(())

    client = SpyClient()
    assert list(client.list_issues()) == []
    client.create_issue({"title": "Task"})
    client.create_comment(4, "claim")
    client.set_issue_labels(4, ["claimed"])
    client.get_pull(9)
    client.get_tree("a" * 40, recursive=True)
    client.create_check_run({"name": "verify", "head_sha": "b" * 40})
    client.update_ref("heads/main", "c" * 40)
    client.merge_pull(9, "d" * 40)
    assert list(client.list_labels()) == []
    client.create_label({"name": "open", "color": "c2e0c6"})
    client.create_pull({"title": "Task", "head": "fork:topic", "base": "main"})
    assert client.calls == [
        ("GET", "/repos/acme/game/issues?state=all", {}),
        ("POST", "/repos/acme/game/issues", {"body": {"title": "Task"}, "expected": (201,)}),
        ("POST", "/repos/acme/game/issues/4/comments", {"body": {"body": "claim"}, "expected": (201,)}),
        ("POST", "/repos/acme/game/issues/4/labels", {"body": {"labels": ["claimed"]}}),
        ("GET", "/repos/acme/game/pulls/9", {}),
        ("GET", "/repos/acme/game/git/trees/" + "a" * 40 + "?recursive=1", {}),
        ("POST", "/repos/acme/game/check-runs", {"body": {"name": "verify", "head_sha": "b" * 40}, "expected": (201,)}),
        ("PATCH", "/repos/acme/game/git/refs/heads/main", {"body": {"sha": "c" * 40, "force": False}}),
        ("PUT", "/repos/acme/game/pulls/9/merge", {"body": {"expected_head_sha": "d" * 40}, "expected": (200,)}),
        ("GET", "/repos/acme/game/labels", {}),
        ("POST", "/repos/acme/game/labels",
         {"body": {"name": "open", "color": "c2e0c6"}, "expected": (201,)}),
        ("POST", "/repos/acme/game/pulls",
         {"body": {"title": "Task", "head": "fork:topic", "base": "main"}, "expected": (201,)}),
    ]


def test_create_pull_posts_to_the_pulls_endpoint_and_requires_201():
    opener = FakeOpener(FakeResponse({"number": 12}, status=201))
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token", opener=opener)
    payload = {"title": "Task 3", "head": "contrib:task-3", "base": "main", "body": "Closes #3"}
    assert client.create_pull(payload) == {"number": 12}
    request = opener.requests[0]
    assert request.get_method() == "POST"
    assert request.full_url == "https://api.github.test/repos/acme/game/pulls"
    assert json.loads(request.data) == payload


def test_create_pull_rejects_a_non_201_status_and_maps_422_to_github_error():
    client = GitHubClient(
        "https://api.github.test", "acme", "game", lambda: "token",
        opener=FakeOpener(FakeResponse({"number": 12}, status=200)),
    )
    with pytest.raises(GitHubError, match="unexpected response status"):
        client.create_pull({"title": "Task", "head": "contrib:task", "base": "main"})

    error = urllib.error.HTTPError(
        "https://api.github.test/repos/acme/game/pulls", 422, "Unprocessable",
        {}, io.BytesIO(json.dumps({"message": "A pull request already exists"}).encode()),
    )
    failing = GitHubClient(
        "https://api.github.test", "acme", "game", lambda: "token", opener=FakeOpener(error))
    with pytest.raises(GitHubError) as excinfo:
        failing.create_pull({"title": "Task", "head": "contrib:task", "base": "main"})
    assert excinfo.value.status == 422


def test_create_label_requires_201_and_list_labels_paginates():
    opener = FakeOpener(
        FakeResponse([{"name": "open"}],
                     headers={"Link": '<https://api.github.test/repos/acme/game/labels?page=2>; rel="next"'}),
        FakeResponse([{"name": "done"}]),
        FakeResponse({"name": "claimed"}, status=201),
    )
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token", opener=opener)
    assert [label["name"] for label in client.list_labels()] == ["open", "done"]
    assert client.create_label({"name": "claimed", "color": "fbca04"}) == {"name": "claimed"}
    assert opener.requested_urls == [
        "https://api.github.test/repos/acme/game/labels",
        "https://api.github.test/repos/acme/game/labels?page=2",
        "https://api.github.test/repos/acme/game/labels",
    ]
