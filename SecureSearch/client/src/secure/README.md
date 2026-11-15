# Secure Search v2

Secure v2 is an isolated client-side workflow alongside the legacy HMAC
application.

## Implemented path

1. The user creates/unlocks a browser vault with a passphrase. The vault
   envelope is encrypted with PBKDF2-SHA-256 + AES-256-GCM and stored in
   IndexedDB.
2. Supported files are read in the browser. Searchable text is normalized
   using NFKC, lowercase and Unicode letter/number tokenization.
3. The original file payload (including its filename and MIME type) is
   encrypted with a fresh per-document AES-256-GCM key. The content key is
   stored only inside the encrypted vault state.
4. Diana update tokens are generated in the browser. The server receives
   opaque addresses and masked document indexes. Client counters advance only
   after the server acknowledges the posting, and the updated vault is saved.
5. The client maintains a local authenticated-leaf set and trusted Merkle root.
   Search derives the full expected address set locally, fetches the matching
   records, checks the server root against the locally held root, verifies
   each inclusion proof, and checks exact expected-address-set equality.
6. Conjunctive queries are processed as independent Diana searches and
   intersected locally. Matching files are retrieved with a Merkle proof and
   decrypted in the browser.

## Current supported file types and limits

Secure v2 currently supports TXT, CSV, Markdown, JSON, HTML, XML and LOG files,
up to 5 MB each. PDF, Office and OpenDocument files remain on the legacy path
until browser-side extractors are integrated. The legacy upload and search
routes are unchanged.

## Security and research limitations

- This implementation is an integration milestone, not a production-audited
  cryptographic system.
- The Diana prototype has not yet been differentially checked against the
  upstream OpenSSE implementation; its interoperability must be established
  before claiming exact scheme conformance.
- The server sees opaque update addresses and the posting addresses requested
  during search. Search access-pattern leakage remains.
- The Merkle root is trusted because it is computed and retained by the
  client in its encrypted vault. A lost/reset vault cannot securely recover
  that root from the server without a trusted checkpoint.
- The authenticated map currently rebuilds the full owner tree for proofs and
  is capped at 49,999 records. This is a correctness-first prototype, not a
  scalable dynamic authenticated data structure.
- Deletion/backward privacy, multi-device concurrent writers, key recovery,
  rollback protection across devices, and secure migration of legacy
  documents are not implemented.
- The client currently persists the vault after each posting. If a batch is
  interrupted, already acknowledged postings remain committed and the vault
  records that partial progress; the document may need to be re-uploaded.
- Do not store plaintext Diana serialization outside the encrypted vault.
