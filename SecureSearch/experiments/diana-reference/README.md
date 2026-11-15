# OpenSSE Diana compatibility oracle

This directory contains a small independent C++ oracle used to compare the TypeScript Diana implementation against the cryptographic construction used by OpenSSE.

## Pinned upstream sources

- OpenSSE schemes repository: https://github.com/OpenSSE/opensse-schemes
- Schemes tree: `084e80bb1223560d30024b7d20b165e3dfc64426`
- Crypto toolkit submodule: `60b0db0bbdf2b2c0257cc11e3f06b10ff90636a5`
- Diana client: `lib/include/sse/schemes/diana/diana_client.hpp`
- Diana token/mask splitting: `lib/diana/diana_common.cpp`
- Diana type sizes: `lib/include/sse/schemes/diana/types.hpp`
- Crypto PRF: `src/include/sse/crypto/prf.hpp`
- Crypto PRG: `src/prg.cpp`
- Crypto hash: `src/hash/blake2b.cpp`
- Crypto constrained PRF: `src/include/sse/crypto/rcprf.hpp`

## What the oracle covers

The C++ program independently implements the relevant upstream semantics:
1. BLAKE2b-512 keyword hashing, truncated to 16 bytes.
2. HMAC-BLAKE2b PRF evaluation with 32-byte keys and 32-byte output.
3. The 48-level GGM tree using original ChaCha20, zero 8-byte nonce and byte offsets.
4. 16-byte update token and following 8-byte document-index mask.

The deterministic vectors use master keys filled with `0x11` and `0x22`, keyword `cloud`, and leaves 0–2. The JSON fixture is the expected output of the C++ oracle.

## Reproduce

From this directory:

```bash
g++ -std=c++17 opensse-diana-oracle.cpp -lcrypto -o opensse-diana-oracle
./opensse-diana-oracle > opensse-vectors.generated.json
diff -u ../../client/src/secure/diana/fixtures/opensse-vectors.json opensse-vectors.generated.json
```

GitHub Actions performs this regeneration and diff before running Vitest.

## Important scope limitation

This is a cross-language compatibility oracle based on pinned OpenSSE/crypto-tk source semantics; it does **not** compile or execute the upstream OpenSSE binary. It validates deterministic primitive and RCPRF outputs, not RPC behavior, persistence, leakage, security proofs, or production security. Upstream OpenSSE itself describes the project as research software and warns against using it for sensitive production data.
