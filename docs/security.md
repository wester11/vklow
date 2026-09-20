# Security notes

Subscription URLs are stored through the `SecretStore` abstraction. On Windows the current implementation uses maintained `keyring` 4.x with its native Windows Credential Manager store instead of writing secrets or encryption keys into application files. The dependency is dual-licensed MIT/Apache-2.0; platform-specific storage remains isolated behind the abstraction.

Normal frontend DTOs contain subscription metadata only. They never expose a stored URL, access token, password, or Xray runtime configuration.
