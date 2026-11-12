# SecureSearch — local privacy-preserving document search

A complete local-first full-stack project. Register, upload documents, extract text from supported formats, encrypt the original file and extracted text with AES-256-GCM, create keyed HMAC keyword tokens, and search for documents containing **all** query terms.

## Important design note

This is a practical educational searchable-encryption prototype inspired by the paper *Towards efficient privacy-preserving conjunctive keywords search over encrypted cloud data* (Liu et al., Future Generation Computer Systems 166, 2025, 107716). It is **not a faithful implementation or security proof of the paper's Multi-Bitmap Index + IBF + full-binary-tree construction**. This version uses a per-user HMAC-SHA-256 keyword index and conjunctive token intersection because it is easier to audit and run locally. It leaks search/access patterns and equality of keyword tokens to the server. The server also sees extracted plaintext transiently during upload. Do not use it for highly sensitive production data.

## Features

- JWT registration/login and per-user document isolation
- Upload PDF, DOCX, DOC, XLSX, XLS, PPTX, PPT, CSV, TXT, Markdown, HTML, XML, JSON, RTF, ODT, ODS and ODP
- Extract searchable text, normalize/tokenize it, and create per-user HMAC-SHA-256 tokens
- AES-256-GCM encryption for uploaded bytes and extracted text at rest
- Conjunctive search: every distinct query word must be present in a document
- Download original file (decrypted only after authentication)
- Delete documents and their search tokens
- Search result snippets are generated from decrypted text after a match
- Local MongoDB; no AWS or cloud service required

## Requirements

- Node.js 20+
- npm 10+
- MongoDB Community Server running locally

## Run locally on Windows

1. Start MongoDB locally (no cloud account or service is required). With Docker Desktop:

   ```powershell
   docker run --name securesearch-mongodb -p 127.0.0.1:27017:27017 -v securesearch-mongodb-data:/data/db -d mongo:8.0
   ```

   The named volume preserves database files between container restarts, and the port is bound to this computer only. To start or stop this existing container later, use `docker start securesearch-mongodb` or `docker stop securesearch-mongodb`.

   Alternatively, install MongoDB Community Server as a Windows service:

   ```powershell
   winget install --id MongoDB.Server --exact --accept-package-agreements --accept-source-agreements
   ```

   If setup did not start the service, open PowerShell as Administrator and run `Get-Service *mongo*` followed by `Start-Service MongoDB`.

2. From the project root, copy the example configuration and generate local secrets:

   ```powershell
   Copy-Item .env.example .env
   $jwt = node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))"
   $key = node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))"
   (Get-Content .env) -replace '^JWT_SECRET=.*$', "JWT_SECRET=$jwt" -replace '^MASTER_KEY=.*$', "MASTER_KEY=$key" | Set-Content .env
   ```

   The generated values stay in the local, git-ignored `.env` file. Keep `MASTER_KEY` backed up: changing or losing it makes existing documents unreadable. The default MongoDB URL (`mongodb://127.0.0.1:27017/securesearch`) connects to the local MongoDB service.

3. Install dependencies and build both applications:

   ```powershell
   npm install
   npm run build
   ```

4. Start the API and Vite frontend from the project root:

   ```powershell
   npm run dev
   ```

5. Open the local URL printed by Vite (normally http://localhost:5173). Vite proxies `/api` requests to the API on port 5000, including when Vite selects a different frontend port because 5173 is already in use. The API health check is http://localhost:5000/api/health.

Register an account, upload a text or office document, confirm it appears under **My documents**, and search for words contained in the uploaded document. Search requires every distinct query word to be present. The original file can also be downloaded and decrypted by its owner.

To run the production API after building, use `npm start` from the project root. For a different MongoDB URI or port, edit the corresponding values in `.env`.

Backend: http://localhost:5000/api/health

## Build

```bash
npm run build
npm start
```

## Supported file extraction

PDF uses `pdf-parse`; DOCX uses `mammoth`; XLS/XLSX uses `xlsx`; CSV uses `csv-parse`; PPTX/ODT/ODS/ODP and legacy Office formats use `officeparser` as a fallback; text/web formats use built-in parsing and HTML stripping. Extraction depends on the quality and structure of the source file. Scanned PDFs need OCR and are not guaranteed to yield text in this version. Password-protected or malformed files may fail extraction.

## API

- `POST /api/auth/register` — `{ name, email, password }`
- `POST /api/auth/login` — `{ email, password }`
- `GET /api/auth/me` — Bearer token
- `POST /api/documents` — multipart field `file`
- `GET /api/documents` — list metadata
- `GET /api/documents/:id/download` — decrypt and download original
- `DELETE /api/documents/:id` — delete
- `POST /api/search` — `{ query }`

All document endpoints require `Authorization: Bearer <token>`.

## Security and limitations

- AES-GCM authenticates encrypted content. Each encrypted object gets a fresh random IV.
- Per-user keys are derived from `MASTER_KEY` with HKDF-SHA-256 and the user's database ID as salt/context.
- Search terms are normalized to lowercase Unicode words. Punctuation is ignored. All distinct terms must match.
- HMAC tokens are deterministic for a given user and term, so equality/search-pattern leakage exists.
- The server must process plaintext to extract text and build the index. This is not end-to-end encryption.
- Back up `MASTER_KEY`. If it is lost or changed, existing data cannot be decrypted/searched correctly.
- This project is a prototype, not a production security product. Add malware scanning, rate limiting, key rotation, audit logging, backups and a formal security review before production use.
