# VOID Desktop architecture

## Scope of this baseline

Windows desktop client using Tauri 2, Rust and React/TypeScript. The first implemented vertical slice imports untrusted subscription data, normalizes supported endpoints and exposes only redacted server summaries to the UI. It deliberately does not claim a VPN connection until an Xray process is available and ready.

## Boundaries

| Boundary | Responsibility |
| --- | --- |
| `src/` | Presentation, localized UI state and typed Tauri calls. No subscription secrets or Xray invocation. |
| `src-tauri/subscription` | HTTPS retrieval limits, base64 subscription decoding and URI parsing. |
| `src-tauri/domain` | Normalized `Server`, serializable redacted `ServerSummary`, subscription and state-machine data. |
| `src-tauri/core` | Reserved for Xray lifecycle, validated config generation, stdout/stderr redaction and rollback. |
| `src-tauri/storage` | Reserved for versioned normal settings and Windows secure secret storage. |

## Data path

`HTTPS subscription / URI → validate scheme and size → parse → normalize → in-memory activation → redacted summary → UI`.

State replacement is atomic for remote subscriptions: a failed download or parse never changes the active runtime set. Persisted settings and secure storage are intentionally separate future modules; secrets are not written to JSON by this baseline.

## Connection contract

`Idle → Preparing → StartingCore → Connected → Stopping → Idle`, with an explicit `Error` branch. `Connected` is permitted only after a single managed Xray process validates and reaches readiness. The present baseline returns an honest error when the verified core is unavailable; it does not simulate a connection.

## Windows networking boundary

TUN/DNS/routing changes are not made by this baseline. Before those changes, the implementation must use a reversible transaction: snapshot adapter/DNS/routes, apply minimal change, monitor the core, and restore snapshot on explicit disconnect, crash and startup recovery. This protects the host from a broken network state.

## Security constraints

- subscriptions use HTTPS only, a 15-second timeout, three redirects, 2 MiB maximum response and 500 endpoints maximum;
- parser accepts only VLESS, VMess, Shadowsocks and Trojan; `file:` and other schemes are rejected;
- frontend receives no raw URI, UUID, password, token, key or header;
- executable updates will require an allowlisted HTTPS release, checksum verification, atomic activation, smoke test and rollback.
