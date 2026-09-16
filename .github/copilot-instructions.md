# rrdproxy Copilot Instructions

RRDtool Proxy Server (rrdp) is a standalone PHP daemon that lets Cacti offload RRDtool
file access to a remote host, with RSA + fresh-session-AES encrypted client traffic. See
[README.md](../README.md) for the full feature/protocol overview before making
security-sensitive changes.

## Architecture

- `rrdtool-proxy.php` — main daemon entrypoint: forks the master process, sets up admin
  (CLI), client, and replication sockets, and contains most `rrdp_cmd__*` (admin CLI) and
  `rrdp_system__*` (internal plumbing) functions.
- `lib/functions.php` — shared helpers used by every process: `encrypt()`/`decrypt()`
  (RSA+AES wire protocol), path-confinement helpers (`rrdp_resolve_rra_path`,
  `rrdp_command_has_unsafe_path`), atomic file/key-pair writers, logging.
- `lib/client.php` — per-client child process (`interact()`), forked once per connection.
- `lib/__master__.php` and `lib/replicator.php` — near-duplicate implementations of the
  cluster peer / multi-server-replication (MSR) roles (master listens only; replicator also
  dials out to peers). Keep changes to peer-auth/fingerprint logic in sync between the two.
- `lib/wizard.php` — interactive first-run/reconfiguration setup wizard.
- `cli/removespikes.php` — standalone RRD spike-removal tool, also invoked as a child
  process by the client handler.
- `include/global.php` — constants, severity levels, and CLI help-tree config arrays.

## Build, Lint, and Test

- Install deps: `composer install` (add `--ignore-platform-req=ext-pcntl
  --ignore-platform-req=ext-posix` on Windows dev machines — those extensions are Unix-only
  and only present on the Linux production target).
- `composer run lint` — phplint.
- `composer run phpstan` — `phpstan analyse --level 6` (may need
  `php -d memory_limit=-1` locally; do not lower the configured level to silence findings).
- `composer run phpcsfixer` — dry-run diff; `composer run phpcsfixit` to apply.
- Tests are a plain assertion script, not PHPUnit: `php tests/run.php` (expects
  `OK (<n> checks)`; failures print to STDERR and exit 1).
  - A handful of checks (file permission bits, `AF_UNIX` `socket_create_pair`, path
    separators) are known to fail on Windows but pass on Linux — don't "fix" those unless
    asked; verify by reasoning about the platform difference, not by relaxing the assertion.

## Conventions

- Indent with tabs. Every PHP file starts with the standard Cacti Group GPL header
  comment block (`Copyright (C) 2004-<year> The Cacti Group ...`); `include/global.php`
  computes the display copyright dynamically via `date('Y')`, but the header comments
  themselves are static and need bumping only when explicitly asked.
- Every function has a PHPDoc block: one-line (or short) description, blank `*` line,
  `@param` list, blank `*` line, `@return`. Function signatures are intentionally left
  untyped in code — types live in PHPDoc only, and PHPStan is the source of truth for
  catching mismatches. Don't add native param/return type hints unless asked.
- Encryption uses `phpseclib4\Crypt\*` (namespace root `phpseclib4`, not `phpseclib3`).
  Notable v4 gotchas: there is no `Random` class (use `random_bytes()`); `Rijndael`/AES
  requires an explicit `setIV()` and validates key length strictly (16/20/24/28/32 bytes);
  load keys via `RSA::loadPublicKey()`/`loadPrivateKey()` (or `PublicKeyLoader`) and always
  pass `'md5'` to `getFingerprint()` — the wire protocol and existing client/proxy configs
  store md5 fingerprints, and v4's default changed to sha256.
- New feature/security/behavior changes should get an entry in `CHANGELOG.md` under
  `[Unreleased]`, prefixed `feature:`, `issue:`, or `security:`.
