# Diana prototype test results

Command:

```powershell
npm test
```

Result: **16 passed, 0 failed** (Node.js v22.13.0; TypeScript 5.8.3).

## Verified

- BLAKE2b-512 matches the RFC 7693 empty-message and `abc` vectors.
- HMAC-BLAKE2b-512 matches the pinned output and Node.js/OpenSSL
  `createHmac("blake2b512")`; 32-byte truncation is checked.
- Original ChaCha20 matches Node.js/OpenSSL for the all-zero key/nonce test
  vector, a byte offset within a block, and block counter 1.
- RCPRF range evaluation for the test ranges matches root evaluation for each
  authorized index; prefix `[0,n-1]` round-trips through the reference-layout
  serializer and rejects evaluation at `n`.
- Diana update addresses, masked indices, keyword token, constrained-key bytes,
  and search results match the checked-in deterministic regression fixture.
- Multi-keyword counters, repeated updates, state round-trip, historical
  evaluation, missing server entries, malformed inputs, and the guarded
  `uint32` counter limit are exercised.

## Not verified

- The RCPRF and Diana deterministic fixtures were captured from this
  TypeScript translation. They are not independent reference outputs.
- An OpenSSE C++ executable was not available, so no direct end-to-end
  OpenSSE-vs-TypeScript differential run was performed.
- Passing functional tests does not establish the RCPRF security definition,
  formal forward privacy, resistance to malicious clients/servers, or
  production security.

**Integration gate:** do not integrate this prototype yet. First run a
reproducible differential harness against the pinned OpenSSE source and obtain
an independent cryptographic review of the RCPRF port and serialization.
