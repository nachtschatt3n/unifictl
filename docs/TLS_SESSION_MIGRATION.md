# TLS and session migration (unreleased, after 5.7.0)

This change intentionally tightens authentication defaults. Package version 5.7.0
is unchanged in this proposed patch; assign the release version when accepting
and publishing the change, and include these migration notes in that release.

- New configurations and configurations without `local.verify_tls` verify both
  the certificate chain and hostname. For a private CA, save a PEM bundle with
  `unifictl login --controller-url https://controller.example --username admin --ca-file /path/to/controller-ca.pem`.
  The password is prompted without echo. Relative CA paths in YAML are resolved
  beside that configuration file; login stores the supplied CA path as absolute.
- Existing `verify_tls: false` remains an explicit compatibility setting and
  emits a warning. Migrate it with `login ... --verify-tls`, adding `--ca-file`
  for a private CA. `login ... --insecure` explicitly permits unverified TLS and
  HTTP; do not combine it with a CA bundle. Changing controller clears the old
  TLS exception, CA and fallback setting before applying the new login options.
- Login never follows redirects. Configure the final HTTPS controller URL.
  Login-path discovery only continues on 404/405. Credential rejection, a 2xx
  response without session artifacts, and ambiguous transport failures stop.
  A classic controller that hides a missing endpoint behind 401 (including
  `api.err.LoginRequired`) also stops discovery. A 401 cannot safely distinguish
  an unavailable route from a rejected credential. This controller variant
  still needs validation before upgrading.
- Port 8443 no longer implicitly forwards credentials to port 443. Set the exact
  working URL, or explicitly save `login ... --port-fallback`. Fallback is limited
  to the same scheme, host and path with port 8443 changed to 443, after connection
  failure before sending the request or unavailable login paths. Denials do not
  fall back. `--no-port-fallback` removes that permission for later invocations.
- A project configuration can still override nonsecret fields such as site.
  Changing the controller or username cannot inherit the user's password;
  changing the cloud destination cannot inherit the user's API key. A project
  cannot weaken TLS/CA/fallback policy while inheriting a user password.
  Cloud commands now resolve an API key on demand; a local-only operation needs
  only its controller credentials. In shared checkouts or containers, a project
  configuration owned by another Unix UID is rejected for both local and cloud
  commands. Use a working directory without that project file and store the
  intended settings in the invoking user's private configuration instead.
  `--no-project-config` ignores the current directory's configuration.
- Cached sessions are separate per controller, username and site, and reusable
  only under the same TLS verification mode and CA bytes. Older caches without
  that trust binding require one fresh login, then migrate to `sessions/*.json`.
  No password digest is persisted. Saving changed credentials invalidates that
  principal's cached sessions. The cache remains bounded to 64 entries.
- Before using a restored session for a write, the client checks it with a safe
  site-list read. Expiry can refresh once before the write; failed validation
  sends no write. A principal unable to list sites cannot use a cached token for
  a write. A fresh login does not need this cache preflight. A client refreshes
  at most once; rejected logins do not repeat across a multi-request command.
  `login validate --local-only` checks the supplied password, not merely a cached
  token, and failed validation returns a failing exit status.
- Unix config/cache reads use an owned regular-file handle with no-follow;
  private writes use an atomic sibling replacement and mode 0600. Existing user
  configuration symlinks are resolved explicitly: their target is checked, read
  and replaced while the symlink is preserved. Dangling links and non-files fail;
  project/cache file symlinks are not accepted. Off Unix, directory ACLs still
  determine confidentiality; this patch does not install a Windows ACL policy.
- Malformed YAML errors include line and column without echoing source values.
  Repair the file manually, or explicitly use `login --repair-config` with new
  credentials. That option discards all previous malformed configuration fields;
  it does not bypass file type, ownership or symlink checks.

Validation uses synthetic credentials, HTTP mocks and a loopback HTTPS endpoint.
Run `cargo test --locked` and, after building,
`python3 tests/tls_session_probe.py target/debug/unifictl` (Python 3 and OpenSSL
required). The TLS probe tests untrusted certificates, a configured CA, hostname
mismatch and explicit insecure mode. No live controller validation is claimed.
