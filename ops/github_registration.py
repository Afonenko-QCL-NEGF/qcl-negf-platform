#!/usr/bin/env python3
"""Mint one short-lived runner token on a trusted controller, without logging secrets."""

from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import urllib.error
import urllib.request
import uuid


DEFAULT_REPOSITORY = "Afonenko-QCL-NEGF/qcl-negf"
MAX_PAT_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT = 30


class RegistrationError(Exception):
    """A fixed, secret-free diagnostic suitable for stderr."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal diagnostic can echo arbitrary argument values.
        raise RegistrationError("invalid command line; use --help")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def utc_now():
    return datetime.now(timezone.utc)


def validate_repository(repository):
    # Reject path/URL injection and ambiguous dot segments before using the API URL.
    owner = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
    repo = r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9_])?"
    if not re.fullmatch(owner + "/" + repo, repository, flags=re.ASCII):
        raise RegistrationError("invalid repository; expected owner/repository")
    return repository


@contextlib.contextmanager
def open_parent(path):
    """Pin each directory through dirfds, rejecting symlinks at every component."""
    raw = Path(path)
    if not path or ".." in raw.parts or raw.name in ("", ".", ".."):
        raise RegistrationError("invalid file path")
    absolute = Path(os.path.abspath(path))
    descriptor = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open("/", flags)
        for component in absolute.parts[1:-1]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, absolute.name, str(absolute)
    except OSError:
        raise RegistrationError("file admission failed; check path and symlink parents") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_pat(path):
    with open_parent(path) as (parent, name, _):
        descriptor = None
        try:
            # O_NONBLOCK avoids blocking on a FIFO before fstat rejects nonregular input.
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 dir_fd=parent)
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600):
                raise RegistrationError("PAT file must be a regular file owned by the current uid with mode 0600")
            if metadata.st_size > MAX_PAT_BYTES:
                raise RegistrationError("PAT file exceeds 16 KiB")
            content = os.read(descriptor, MAX_PAT_BYTES + 1)
        except OSError:
            raise RegistrationError("PAT file admission failed") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
    if len(content) > MAX_PAT_BYTES:
        raise RegistrationError("PAT file exceeds 16 KiB")
    try:
        pat = content.decode("ascii")
    except UnicodeDecodeError:
        raise RegistrationError("PAT has an invalid format") from None
    if not re.fullmatch(r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})", pat, flags=re.ASCII):
        raise RegistrationError("PAT has an invalid format; expected a supported PAT prefix without whitespace")
    return pat


def ensure_new_output(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise RegistrationError("output admission failed") from None
    raise RegistrationError("output already exists; choose a new path")


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def validate_response(body):
    if len(body) > MAX_RESPONSE_BYTES:
        raise RegistrationError("GitHub response exceeds 64 KiB")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=unique_json_object)
    except (ValueError, UnicodeDecodeError):
        raise RegistrationError("GitHub response is not valid JSON") from None
    if not isinstance(value, dict):
        raise RegistrationError("GitHub response has an invalid schema")
    token, expires_at = value.get("token"), value.get("expires_at")
    if (not isinstance(token, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{20,512}", token, flags=re.ASCII)
            or not isinstance(expires_at, str)
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", expires_at)):
        raise RegistrationError("GitHub response has an invalid token or expiry")
    try:
        expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise RegistrationError("GitHub response has an invalid expiry") from None
    now = utc_now()
    if not now < expiry <= now + timedelta(hours=1):
        raise RegistrationError("GitHub token expiry must be in the future and within one hour")
    return token, expires_at


def request_token(pat, repository):
    url = "https://api.github.com/repos/" + repository + "/actions/runners/registration-token"
    request = urllib.request.Request(url, data=b"{}", method="POST", headers={
        "Authorization": "Bearer " + pat,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "qcl-negf-platform-runner-registration",
        "Content-Type": "application/json",
    })
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            if response.status != 201:
                raise RegistrationError("GitHub HTTP status " + str(int(response.status)))
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        status = int(error.code)
        with contextlib.suppress(Exception):
            error.close()
        raise RegistrationError("GitHub HTTP status " + str(status)) from None
    except RegistrationError:
        raise
    except Exception:
        raise RegistrationError("GitHub request failed; outcome may be unknown; no automatic retry") from None
    return validate_response(body)


def publish_token(parent, name, token):
    """Publish a complete fsynced 0600 file atomically without replacing any entry."""
    temporary = ".github-registration-" + uuid.uuid4().hex
    descriptor = None
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        created = True
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(token.encode("ascii"))
        while remaining:
            count = os.write(descriptor, remaining)
            if count == 0:
                raise OSError("short write")
            remaining = remaining[count:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        # linkat has exclusive creation semantics; rename would overwrite a racing entry.
        os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    except OSError:
        raise RegistrationError("token publication failed; output was not overwritten") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                os.unlink(temporary, dir_fd=parent)
                os.fsync(parent)
            except OSError:
                raise RegistrationError("token file cleanup or directory sync failed; inspect the selected output directory") from None


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--pat-file", required=True, help="controller-only PAT file: current uid, mode 0600, no newline")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY, help="GitHub owner/repository")
    parser.add_argument("--output", required=True, help="new token file; never overwrites an existing entry")
    try:
        args = parser.parse_args(argv)
        repository = validate_repository(args.repository)
        with open_parent(args.output) as (parent, name, absolute):
            ensure_new_output(parent, name)
            pat = read_pat(args.pat_file)
            token, expires_at = request_token(pat, repository)
            publish_token(parent, name, token)
        print(json.dumps({"path": absolute, "expires_at": expires_at}))
        return 0
    except RegistrationError as error:
        print("github-registration: " + str(error), file=sys.stderr)
    except KeyboardInterrupt:
        print("github-registration: interrupted; request outcome may be unknown", file=sys.stderr)
    except Exception:
        # Never print exceptions: their text may include credentials or response bodies.
        print("github-registration: operation failed; no automatic retry", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
