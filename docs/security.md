# Core-manager security review

## Current controls

- Supported subscription schemes are allowlisted; remote subscriptions are HTTPS-only, redirect-limited and size-limited.
- Parsed credentials never cross the Rust-to-UI boundary.
- CalVer input is validated; free-form version strings are rejected.
- SHA-256 is checked against the selected official `.dgst` entry before a future install is permitted.
- Generated Reality config binds SOCKS exclusively to `127.0.0.1`; it does not expose a LAN proxy.
- Diagnostic redaction is unit-tested with UUID and token fixtures.
- The current implementation does not invoke a shell or execute an Xray binary.

## Required before enabling downloader/process execution

- stage the ZIP in the app-private data directory and reject traversal paths during extraction;
- verify `xray.exe` is the expected staged regular file, run `version` without a shell, then atomically activate;
- retain previous known-good version and never replace a running binary;
- apply a readiness timeout and terminate orphaned child processes;
- persist subscription secrets in Windows credential storage, separately from metadata.
