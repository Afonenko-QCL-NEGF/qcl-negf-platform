# Actual nginx bootstrap preflight

`ops/bootstrap_build.py preflight --check-nginx` builds only the evaluated
`nginx.conf` writer and runs the configuration's actual nginx executable with
`-t`. Writer/gixy success alone is insufficient: a cached config can still omit
`ssl_certificate` for an explicit SSL listener.

The receipt binds the generated store file to the actual NixOS `ExecStart` (or
the `/etc/nginx/nginx.conf` source when reload is enabled), records its SHA256,
the test configuration SHA256 and the substituted TLS paths, and retains bounded
stdout/stderr on failure. Acceptance requires actual nginx syntax-test success
and zero `warn/error/crit/alert/emerg` counters. Evaluation without `--check-nginx`
remains `evaluation_only`; build success without the native test never gives `pass`.

Run this only on an admitted trusted builder. The namespace entry is an explicit
operator choice, not an implicit grant of sudo to a CI runner. For a trusted
builder whose reviewed sudo policy permits root namespaces:

```sh
python3 ops/bootstrap_build.py --receipt /absolute/new-preflight.json preflight \
  --site /absolute/private-site --nix /run/current-system/sw/bin/nix --check-nginx \
  --openssl /absolute/measured/openssl --mount /absolute/measured/mount \
  --nginx-namespace '["/run/current-system/sw/bin/sudo","-n","/run/current-system/sw/bin/unshare","--mount","--net","--propagation","private"]'
```

A root operator can omit the sudo prefix. A site that supports unprivileged user
namespaces can explicitly choose `unshare --user --map-root-user --mount --net`.
The child checks distinct mount and network namespaces and mapped root **before**
mounting anything, makes propagation private, and uses namespace-private
`/run`, `/var/log`, `/var/cache` and `/tmp`. Unsupported namespaces, missing
executables or denied permissions fail closed. No listener or guest service is
started. Each child retains the helper's 60-second/1 MiB limits; the admitted
producer must also supply an overall budget.

Only the evaluated certificate/key directive paths are replaced with a fresh
engineering certificate and key. Production TLS material is never read by this
check, and runtime credential readability remains a separate deployment gate.
Unexpected certificate directives and missing configured directives fail rather
than being omitted. Other generated config bytes remain unchanged.

`tofu/build-images.ts` requires the public preflight receipt explicitly:

```sh
deno run --allow-read --allow-run=nix --allow-write=OUTPUT_DIRECTORY tofu/build-images.ts \
  SITE_FLAKE PROXMOX_BASE.json - OUTPUT_DIRECTORY \
  --preflight-receipt /absolute/new-preflight.json
```

Without the flag or a passed actual-test receipt, the default entry point fails
before reading input files or invoking an image build. It compares all four
freshly evaluated role derivations, the actual nginx executable/ExecStart,
writer derivation/output and the actual config SHA256 to the receipt. It also
requires native exit0, syntax-success diagnostics and zero severity counters.
Use an Arch base JSON file instead of `-` when that optional image is included.
The native check is not duplicated in the image adapter. Flake URI inputs remain
supported; a receipt made from a matching local checkout is accepted only when
the derivations and actual config contents match exactly. Receipt timestamps
alone never establish this correspondence. No signing or content trust checks
are relaxed by the engineering receipt.
