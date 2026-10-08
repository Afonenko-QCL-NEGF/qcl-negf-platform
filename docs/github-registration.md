# Controller-side GitHub runner registration

`ops/github_registration.py` requests one repository runner registration token.
Run it only on the trusted deployment controller. The PAT stays on that controller;
the guest receives only the resulting short-lived registration token. Neither
credential belongs in Git, a Nix derivation, OpenTofu variables/state, command-line
arguments, or logs.

```console
python3 ops/github_registration.py \
  --pat-file /private/controller/github-runner.pat \
  --repository Afonenko-QCL-NEGF/qcl-negf \
  --output /private/controller/new-runner-registration.token
```

Provision the PAT file through the controller's existing secret mechanism. It must
be a regular file owned by the invoking uid, with mode `0600`, at most 16 KiB, and
contain a supported `ghp_` or `github_pat_` PAT without whitespace or a trailing
newline. Every path component must be a real directory rather than a symlink.
The output directory must already exist; the output filename must be new.

The CLI makes a single authenticated `POST` to GitHub's
[repository runner registration-token endpoint](https://docs.github.com/en/rest/actions/self-hosted-runners#create-a-registration-token-for-a-repository).
Verified TLS uses Python's default SSL context. Environment proxy settings and
redirects are disabled. The request has a 30-second socket timeout, and the response
body is capped at 64 KiB. The CLI accepts only HTTP `201`, a valid token, and an
expiry in the future within one hour. Earlier successful PAT reads or HTTP `200`
responses do not prove permission to create a registration token.

Expiry accepts RFC3339 with `Z` or an explicit numeric offset such as `+00:00` or
`+03:00`, including up to nine fractional digits. The validator converts the same
instant to UTC and floors to whole seconds, so normalization never extends token
lifetime. Unknown-offset `-00:00`, missing zones and malformed numeric offsets
are rejected. The HTTP issuer Date must remain within five seconds of local UTC;
canonical expiry must be strictly in the local future and at most one hour after
that verified issuer Date. Numeric offsets change representation, not these clock
or lifetime rules. JSON duplicates and the 64 KiB response bound remain rejected.

After validating the response, the CLI writes and fsyncs a mode `0600` regular file,
then publishes it atomically using exclusive hard-link creation. It never replaces
an existing path, including a symlink or a path created during the HTTP request.
The file contains the ASCII token without a newline, matching the guest's token
file contract. Stdout contains only JSON `path` and `expires_at` metadata; stderr
contains fixed diagnostics and, for HTTP errors, the status code. It never emits
the PAT, token, headers, response body, or an underlying exception message.

Transfer only this token file through the deployment's authorized private runtime
secret path and register the guest before `expires_at`. Keep the PAT on the
controller. The pinned persistent NixOS runner compares the token file on each
restart, so retain its root-only vault/runtime copies unchanged even after expiry.
Deleting or changing those copies requires fresh registration. After replacing a
vault token, restart the site's credential publication oneshot first, then restart
the runner; an already-active `RemainAfterExit` unit does not republish automatically.
Remove controller-side temporary files through the controller's secret lifecycle.
The CLI does not register a guest, transfer files, or run scientific workloads.

There are no automatic retries. A transport error or interruption can leave the
request outcome unknown. Inspect the controller's deployment state before issuing
another request, and always choose a new output path. A server-issued token that
could not be published locally expires according to GitHub's response.

Focused verification uses only synthetic credentials and mocked HTTP boundaries:

```console
python3 -m unittest discover -s tests/operations -p test_github_registration.py -v
```

These tests establish local file admission, request construction, TLS/proxy/redirect
configuration, response validation, error sanitization, and exclusive publication.
They do not establish a real PAT's permissions, guest registration, CI execution,
VM boot, or scientific correctness.
