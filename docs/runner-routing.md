# Site-defined runner name resolution

Runner routing is disabled by default. A private site may opt in by supplying
both runtime files and the units that provision them:

```nix
qclNegf.runner.routing = {
  hostsFile = "/run/site-runner-routing/hosts";
  nsswitchFile = "/run/site-runner-routing/nsswitch.conf";
  units = [ "site-runner-routing.service" ];
};
```

The site owns the file contents and their runtime provisioning. Keep the files
root-owned and readable through the runner namespace, with restrictive ownership
on their source directory. Supply canonical absolute paths outside the Nix store;
whitespace, `:`, `%` specifiers, empty components and `.` or `..` components are rejected. Setting
only one file fails configuration assertions.

The module binds these files read-only over `/etc/hosts` and `/etc/nsswitch.conf`
in each configured runner service. It also hides `/run/nscd` in those services.
glibc can forward name lookups to the host's NSCD-compatible daemon before using
the caller's NSS configuration; that daemon sees the host's files rather than
the runner's mounted files. The optional inaccessible-path prefix accommodates
hosts without that daemon. It does not make the two file binds optional.

Runner startup requires the provisioning units, runs after them, and requests
the mounts needed for the token directory and both runtime files. A missing
source file prevents the namespace bind and service startup. The site must
provision the files before starting the service; the module does not generate
hosts or NSS content. Other host services retain their original configuration.

Preserve the site's existing NSS databases and explicitly place `files` first
for the hosts database when using hosts overrides. Verify the resulting namespace
with the actual runner UID: check its username and UID lookup, root UID lookup,
and the intended hostname resolution. Hiding the host daemon can expose missing
NSS modules for other databases, so check any dynamic or directory-backed
identities the site uses. A successful check for fixed local accounts does not
establish that every NSS database works.

Transport admission remains separate: verify TLS against the original hostname,
keep certificate checks enabled, measure the route, and bound any temporary
transport's lifetime. This option does not provide a proxy, credentials,
registration retries, workflow dispatch or broader runner privileges. Existing
scientific isolation paths and resource slice settings remain in force.

The focused evaluation fixture is `tests/runner-nss.nix`. It checks merged NixOS
options with routing disabled and enabled, rejects incomplete and ambiguous
paths, and verifies read-only binds, daemon isolation, provisioning dependencies
and existing runner isolation. Runtime name resolution and complete runner
registration require separate site evidence.
