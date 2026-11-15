# Automated SecureSearch benchmark

This benchmark compares the Legacy HMAC search path and Secure v2 using the same 10 public documents:
- 5 recent SEC EDGAR 8-K filings (Apple, Microsoft, Visa, Amazon and NVIDIA).
- 5 recent Federal Register notices.

It downloads the documents itself, extracts visible text, caps each normalized document at 20 KiB, and writes a source manifest. No manual upload is required.

## Safety first
- The runner creates a uniquely named temporary benchmark user.
- It uploads documents only under that temporary account.
- Secure v2 uses an in-memory IndexedDB polyfill; its temporary vault/passphrase are not stored in your browser.
- It attempts to delete only the temporary user's Legacy documents, SecureRecord rows and User record.
- It does not delete existing user data.
- If the process is forcibly terminated, cleanup may not run. Check for a recent user whose email begins `securesearch-benchmark-` before manually cleaning anything.
- **Recommended:** run against a dedicated local test database first, not your main Atlas database. MongoDB may not immediately return allocated storage after deletion.
- SEC requires a descriptive User-Agent containing a contact email. Set it locally; do not commit it.

## Prerequisites
- Node.js 20+
- SecureSearch API running and connected to the intended test MongoDB database
- Dependencies installed

From the SecureSearch project root:

```powershell
npm install
```

Set your SEC contact header and run:

```powershell
$env:SEC_USER_AGENT = "SecureSearch benchmark contact your-email@example.com"
npm run benchmark --workspace server
```

Optional API URL:

```powershell
$env:BENCHMARK_API_URL = "http://127.0.0.1:5000"
```

The script reads the same `.env` and MongoDB URI as the server. For an isolated local database, set `MONGODB_URI=mongodb://127.0.0.1:27017/securesearch_benchmark` in `.env` and restart the API before running it.

## Output
A timestamped folder is created under `benchmark-results/`:
- `dataset_manifest.csv`: document title, official source URL, original response size, normalized text size and query term.
- `upload.csv`: end-to-end upload time for each implementation/document.
- `search.csv`: five measured searches per document after one warm-up, result count, expected-document correctness and local Diana trapdoor time.
- `storage.csv`: database and collection snapshots before upload, after each implementation, before cleanup and after cleanup.
- `summary.csv`: mean upload time, mean/median search time and correctness count.
- `documents/*.txt`: exact normalized text used in the run.

## Interpretation
- These are measurements from the machine, network and MongoDB instance used for the run, not values copied from papers.
- Upload and search times are end-to-end and include network/API overhead. They are not pure cryptographic primitive timings.
- Secure v2 search includes Diana address derivation, proof retrieval, digest/Merkle verification, result intersection and document decryption.
- Legacy search includes HMAC lookup, MongoDB query and snippet generation.
- The script reports MongoDB storage snapshots; allocation and index storage may not shrink immediately after cleanup.
- The initial runner does not isolate server CPU time or standalone AES/Merkle primitive time. Those require additional server/client instrumentation.

## Troubleshooting
- Start the API before running the script.
- If SEC rejects requests, use a valid contact email in `SEC_USER_AGENT` and retry later.
- If fewer than five documents are returned by either source, the run stops before registering the benchmark user.
- If cleanup reports failure, inspect the temporary benchmark account and delete only its records after confirming the owner ID.
