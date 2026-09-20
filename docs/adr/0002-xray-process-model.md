# ADR 0002: managed Xray process

**Status:** accepted

Xray-core is treated as an independently versioned executable. It must be acquired only from an approved HTTPS release flow, validated with a published checksum, staged outside the active directory, smoke-tested, then atomically activated while retaining the previous version for rollback.

The UI must not report `Connected` based on a timer or process-spawn attempt. The Core Manager owns PID tracking, stdout/stderr redaction, readiness timeout, single-instance locking, graceful termination and crash propagation to the connection state machine.

Xray-core is MPL-2.0; its notice is included in `THIRD_PARTY_NOTICES` before distributing it.
