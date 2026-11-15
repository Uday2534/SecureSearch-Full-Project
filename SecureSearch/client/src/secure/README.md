# Secure Search v2 client primitives

This folder contains browser-side foundations for the forward-private search
integration.

- `crypto.ts`: PBKDF2-SHA-256 key derivation, AES-256-GCM vault envelopes,
  per-document AES-GCM keys, and SHA-256 helpers.
- `vaultStorage.ts`: stores only encrypted vault envelopes in IndexedDB.
- `api.ts`: typed access to the isolated opaque-record API.
- `merkle.ts`: verifier for SHA-256 Merkle inclusion proofs.

## Security boundary

The vault passphrase and Diana client master keys must remain in the browser.
Persist only the encrypted vault envelope; never persist serialized Diana
state or raw key bytes in localStorage, sessionStorage, or ordinary server
records. Unlocking should keep keys in memory and lock them again when the
user signs out or the tab is closed.

Document content keys are exported only so they can be included inside the
vault state before that state is encrypted. They must never be sent separately
to the server.

The inclusion-proof verifier proves that a returned key/value pair belongs
to the committed tree. It does **not** prove that the server returned every
match. Search completeness must additionally compare the returned address
set against the full expected address set independently derived by the Diana
client.

The opaque API stores client-produced values but does not yet implement a
Merkle-authenticated map, Diana request evaluation, or a complete upload/search
workflow. This code has not yet undergone a browser build, interoperability,
or security review.
