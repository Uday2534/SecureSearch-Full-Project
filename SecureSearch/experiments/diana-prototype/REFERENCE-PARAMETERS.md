# Diana reference parameters and format

This document records the concrete OpenSSE Diana profile translated by the
prototype. The paper defines the construction in terms of cryptographic
primitives; several values below are OpenSSE implementation choices, not
universal constants required by the paper.

## Diana parameters

| Item | OpenSSE profile |
|---|---|
| Derivation master key | 32 random bytes |
| Keyword-token master key | 32 independent random bytes |
| Keyword index | First 16 bytes of BLAKE2b-512 of the keyword bytes |
| Per-keyword RCPRF root | HMAC-BLAKE2b output truncated to 32 bytes |
| Keyword token | HMAC-BLAKE2b output truncated to 32 bytes |
| RCPRF tree height | 48 |
| RCPRF leaf value | 32 bytes |
| PRG | Original ChaCha20, 32-byte key, all-zero 8-byte nonce, 64-bit block counter |
| Update address | First 16 PRG bytes |
| Document-index mask | Next `sizeof(index)` PRG bytes; 8 bytes for OpenSSE `uint64_t` |
| Counter storage | OpenSSE `uint32_t`, stores the latest assigned zero-based index |
| Search count | `add_count = latest_index + 1`, represented as `uint32_t` |

`RCPrfParams::max_leaf_index(height)` is `(1 << (height - 1)) - 1` for the
height used here. Therefore height 48 spans indices `0` through `2^47 - 1`.
The Diana counter and `add_count` are narrower than this tree. This prototype
stores a count (rather than the last index) and refuses an update when the
count is already `0xffffffff`, so it never wraps `add_count`. The highest
accepted count is `0xffffffff`, with assigned indices ending at
`0xfffffffe`.

The reference counter behavior is: first update uses index 0 and stores 0;
subsequent updates increment and use the new index. A search reads the stored
last index and sets `add_count` to that value plus one. The prototype's count
`n` corresponds to reference last-index `n-1`.

## Tree PRG and range constraints

For a 32-byte node key, the PRG is the original DJB ChaCha20 stream. Child keys
are 32-byte windows at offsets 0 and 32. The left/right decisions follow the
leaf-index bits from most-significant to least-significant. The final
32-byte leaf value is a window at offset `branch * 32` in the last parent
stream.

To constrain an inclusive interval, OpenSSE emits maximal complete subtrees
covering only that interval. A subtree element includes its subtree height,
minimum and maximum leaf, and key. A single-leaf element contains the leaf
value itself. The prototype uses the same range partition and evaluation
semantics; the server evaluator does not receive the RCPRF root.

## Constrained-key serialization

OpenSSE serializes `ConstrainedRCPrf<32>` with native `memcpy` field writes.
On the reference's common x86/x86-64 little-endian target, the bytes are:

1. `tree_height`: 1 byte.
2. `element_count`: 4-byte little-endian unsigned integer.
3. For each element in traversal order:
   - `subtree_height`: 1 byte.
   - `min_leaf`: 8-byte little-endian unsigned integer.
   - `max_leaf`: 8-byte little-endian unsigned integer.
   - `key`: 32 bytes.

There is no element-kind tag. A leaf element is identified by
`subtree_height == 1` and `min_leaf == max_leaf`; other valid elements are
inner subtrees. Each serialized element occupies 49 bytes.

OpenSSE does not define a standalone serialized wire format for the complete
`SearchRequest` structure. The prototype exposes the request fields separately:
32-byte keyword token, constrained-key bytes (or `null` for an absent keyword),
and `add_count`. Any future network envelope must document its own encoding
rather than claiming it is an OpenSSE format.

The C++ serializer is native-endian. The prototype's explicit little-endian
encoding matches x86/x86-64 OpenSSE output, but does not claim compatibility
with an OpenSSE build on a big-endian machine.

## Validation and deviations

- Tree height, key sizes, keyword index, HMAC truncation, PRG offsets, update
  address/mask split, and constrained-key field layout follow the cited source.
- The prototype enforces canonical aligned subtree intervals, ordered and
  disjoint elements, exact prefix coverage, and exact buffer length when
  deserializing. OpenSSE's generic deserializer is less strict in several of
  these checks.
- It refuses the `uint32` count wraparound boundary rather than reproducing
  the reference's overflow behavior.
- It stores the number of additions per keyword; OpenSSE stores the most
  recently assigned index.
- It advances a counter only after token generation succeeds. OpenSSE
  increments its counter before completing the request generation.
- It rejects duplicate update addresses and reports a missing server entry as
  an error. OpenSSE's sample server logs a missing entry and continues with
  partial results.
- It uses Node's CSPRNG for setup. OpenSSE uses its crypto toolkit CSPRNG.
- Its JSON client-state snapshot is an experimental convenience, not an
  OpenSSE persistence or wire format.
- The test suite cross-checks BLAKE2b against RFC 7693 and HMAC-BLAKE2b /
  original ChaCha20 against Node.js/OpenSSL. No direct OpenSSE executable
  differential was available. The included Diana/RCPRF values are regression
  vectors from this translation and are not an independent proof of
  equivalence.

These are conformance observations, not a security review or a claim that the
prototype is secure.
