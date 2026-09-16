# Changelog

All notable changes to RRDtool Proxy Server are documented in this file.
Entries are prefixed `security:`, `issue:`, or `feature:`.

## [Unreleased]

- feature: Bump the minimum supported PHP version to 8.2.
- feature: Upgrade the phpseclib dependency from phpseclib 3 to phpseclib 4 (Composer-managed).
- feature: Migrate encryption from the unmaintained, manually vendored phpseclib 1.x/2.x copy to the Composer-managed phpseclib 3 package.
- issue: Fix `lib/__master__.php` and `lib/replicator.php` calling phpseclib 1.x/2.x-only methods (`loadKey()`, `getPublicKeyFingerprint()`) that do not exist in phpseclib 3/4, which fataled the replicator/MSR peer-authentication code path at runtime.
- security: Encrypt the "request too large" error response for authenticated clients instead of returning it in plaintext.
- issue: Inherit the full child-process environment for `removespikes` instead of the subset populated in `$_ENV` (was silently dropping variables such as `TEMP` on Windows).
- issue: Add the missing space in the `RRDTOOL_PIPE_UNAVAILABLE` error frame so it matches other error responses.
- issue: Check the `symlink()` return value in the test fixtures instead of risking a false positive when symlinks are unavailable.
- security: Use constant-time `hash_equals()` comparisons for RSA public-key fingerprint verification.
- security: Bound encrypted and compressed request frames and fail closed on malformed or oversized input.
- security: Confine RRDtool and filesystem operations to the configured RRA root; reject path traversal, absolute paths, and embedded command framing.
- security: Remove shell interpolation from RRDtool and `removespikes` execution in favor of argv-based process invocation.
- security: Make RSA key writes atomic, validate matching key pairs, and enforce `0600` permissions on private key files.
- issue: Fix partial socket writes, RRDtool pipe startup failures, admin disconnect cleanup, and IPv6 admin binding.
