# Diana conformance prototype

This directory is an isolated TypeScript research prototype. It is not imported
by the SecureSearch application and is not a production-ready or audited
cryptographic implementation.

## Implemented

- BLAKE2b-512 and HMAC-BLAKE2b, using `@noble/hashes`.
- OpenSSE's original ChaCha20 stream profile, using `@noble/ciphers`.
- The binary-tree RCPRF and inclusive range constraints used by OpenSSE Diana.
- Diana setup, independent per-keyword counters, update requests, search
  tokens, constrained-key serialization, and server-side evaluation.
- A small in-memory server index for functional conformance tests.

The implementation does not perform keyword normalization. As in OpenSSE, the
UTF-8 bytes of the exact keyword string are hashed. The calling application is
responsible for using the same normalized keyword for updates and searches.

## Algorithm outline

For a keyword `w`, the client computes the first 16 bytes of
`BLAKE2b-512(UTF8(w))`. HMAC-BLAKE2b under the derivation key derives a
32-byte RCPRF root for that keyword. A second HMAC-BLAKE2b key derives the
32-byte keyword token.

Each update evaluates the RCPRF at the current zero-based keyword counter. The
32-byte leaf value keys the original ChaCha20 PRG (8-byte all-zero nonce,
64-bit block counter). The first 16 PRG bytes are the update address; the next
8 bytes mask the 64-bit document index. The counter advances after successful
token generation.

A search with `n` updates sends an RCPRF constrained to `[0, n-1]`, the
keyword token, and `add_count = n`. The server evaluates every allowed leaf,
derives each update address/mask, retrieves the masked index, and unmasks the
document index. OpenSSE's server does not use the keyword token in this
evaluation; it is retained in the request format and reveals repeated-search
equality.

The range restriction comes from the subtree keys in the constrained RCPRF,
not from HMAC key rotation or from an index-only access check. The tests verify
that the evaluator refuses an out-of-range index and that the constrained-key
bytes contain only the authorized subtree material. These are implementation
tests, **not a proof of the RCPRF security definition**.

## Reference and parameter details

See [REFERENCE-PARAMETERS.md](./REFERENCE-PARAMETERS.md) for the concrete
OpenSSE profile, counter mapping, serialization layout, and deliberate
hardening.

Primary sources:

- Raphael Bost, David Minaud, and Olga Ohrimenko, “Forward and Backward
  Private Searchable Encryption from Constrained Cryptographic Primitives,”
  ACM CCS 2017, [IACR ePrint 2017/805](https://eprint.iacr.org/2017/805).
- OpenSSE Diana sources at `opensse-schemes` commit
  `084e80bb1223560d30024b7d20b165e3dfc64426`:
  [`diana_client.hpp`](https://github.com/OpenSSE/opensse-schemes/blob/084e80bb1223560d30024b7d20b165e3dfc64426/lib/include/sse/schemes/diana/diana_client.hpp),
  [`diana_server.hpp`](https://github.com/OpenSSE/opensse-schemes/blob/084e80bb1223560d30024b7d20b165e3dfc64426/lib/include/sse/schemes/diana/diana_server.hpp),
  [`types.hpp`](https://github.com/OpenSSE/opensse-schemes/blob/084e80bb1223560d30024b7d20b165e3dfc64426/lib/include/sse/schemes/diana/types.hpp),
  [`diana_common.cpp`](https://github.com/OpenSSE/opensse-schemes/blob/084e80bb1223560d30024b7d20b165e3dfc64426/lib/diana/diana_common.cpp),
  and [`rocksdb_wrapper.cpp`](https://github.com/OpenSSE/opensse-schemes/blob/084e80bb1223560d30024b7d20b165e3dfc64426/lib/utils/rocksdb_wrapper.cpp).
- OpenSSE crypto toolkit sources at commit
  `60b0db0bbdf2b2c0257cc11e3f06b10ff90636a5`:
  [`rcprf.hpp`](https://github.com/OpenSSE/crypto-tk/blob/60b0db0bbdf2b2c0257cc11e3f06b10ff90636a5/src/include/sse/crypto/rcprf.hpp),
  [`prf.hpp`](https://github.com/OpenSSE/crypto-tk/blob/60b0db0bbdf2b2c0257cc11e3f06b10ff90636a5/src/include/sse/crypto/prf.hpp),
  [`hmac.hpp`](https://github.com/OpenSSE/crypto-tk/blob/60b0db0bbdf2b2c0257cc11e3f06b10ff90636a5/src/include/sse/crypto/hmac.hpp),
  and [`prg.cpp`](https://github.com/OpenSSE/crypto-tk/blob/60b0db0bbdf2b2c0257cc11e3f06b10ff90636a5/src/prg.cpp).

The OpenSSE repositories mark their code AGPL-3.0 and the crypto toolkit
describes itself as research code that should not be used in practice. No
OpenSSE source code is vendored here. Direct package versions and licenses:

- `@noble/ciphers` 1.2.0 — MIT
- `@noble/hashes` 1.8.0 — MIT
- `typescript` 5.8.3 — Apache-2.0
- `@types/node` 22.15.3 — MIT

See `package-lock.json` for the resolved dependency tree.

## Validation

Run from this directory:

```powershell
npm test
```

`test-vectors.json` includes RFC 7693 BLAKE2b vectors, independent
Node.js/OpenSSL HMAC-BLAKE2b and original-ChaCha20 comparisons, plus fixed
RCPRF and Diana regression outputs. The RCPRF/Diana outputs are captured from
this TypeScript translation; they are not represented as a direct OpenSSE
binary comparison.

No OpenSSE C++ binary was available in this environment, so direct end-to-end
differential testing against the upstream executable could not be run. The
prototype follows the cited source algorithms and the primitive outputs are
checked against independent implementations. This limitation must be resolved
with an upstream differential harness and cryptographic review before
application integration.

See [TEST-RESULTS.md](./TEST-RESULTS.md) for the recorded test run and its
conformance limitations.

## Security limitations

- Tests establish functional behavior and byte-level regression only; they do
  not establish forward privacy, pseudorandomness, or implementation security.
- This package has not had an independent security audit.
- `serializeState()` contains raw master keys and counters. It is a test
  convenience only; never persist or transmit that JSON without an independently
  designed, reviewed protection mechanism.
- The original ChaCha20 profile and the binary serialization are retained for
  conformance, not recommended as a general-purpose new protocol.
- This prototype implements insertion/search only. It has no deletion,
  backward privacy, authenticated map, or application integration.
