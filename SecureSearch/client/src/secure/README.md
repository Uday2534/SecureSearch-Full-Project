# Secure Search v2 client primitives

This folder contains browser-only primitives for the forward-private search
integration.

- `crypto.ts`: PBKDF2-SHA-256 key derivation, AES-256-GCM vault envelopes,
  per-document AES-GCM keys, and SHA-256 helpers.
- `merkle.ts`: verifier for SHA-256 Merkle inclusion proofs.

## Security boundary

The vault passphrase and Diana client master keys must remain in the browser.
Persist only the encrypted vault envelope (for example in IndexedDB); never
persist serialized Diana state or raw key bytes in localStorage, sessionStorage,
or ordinary server records. Unlocking should keep keys in memory and lock them
again when the user signs out or the tab is closed.

The inclusion-proof verifier proves that a returned key/value pair belongs to
the committed tree. It does **not** prove that the server returned every match.
Search completeness must additionally compare the returned address set against
the full expected address set independently derived by the Diana client.

These primitives are a foundation, not a completed secure-search workflow.
They are not yet wired into upload/search routes and have not yet undergone
browser build, interoperability, or security testing.
