# CypherSecurity Web Mock

## Run

```bash
cd web
npm ci
npm run build
npm run mock
```

Open `http://localhost:4173`. The mock serves `/api/*` and `web/dist/` on the same origin.

Run the smoke flow:

```bash
npm run mock:smoke
```

Set `BASE_URL` to test another backend:

```bash
BASE_URL=http://localhost:8080 npm run mock:smoke
```

For a cross-origin backend, set `API_BASE` in `web/src/config.ts` to the backend origin and ensure CORS plus credentialed requests are configured.

## Contract assumptions

- Share row JSON is `{id, file_id, file_name, owner:{id,username,fingerprint}, requester:{id,username,fingerprint}, status, note, requested_at, decided_at, delivered_at, imported_at, revoked_at}`.
- List responses use `{ "shares": [...] }`.
- `GET /api/files` includes `access`, `my_pending_request_id`, `pending_requests_count`, and `share_state`.
- Share statuses are `pending`, `approved`, `rejected`, or `revoked`.
- Fingerprints are 64-character hexadecimal strings.
- A malformed or tampered `.cskey` blob returns `400 validation_failed`.
- The mock uses deterministic synthetic wrapped-key bytes and an HMAC signature; it is not cryptographic production behavior.
- The PDF Sign response is `{file_id, signature_count, signed_at, signer_fingerprint}`. Verify responses use `{signed, valid, reason, signatures}`, with each signature containing validity/reason, signer metadata, signing time, and certificate metadata.
- A signature's signer has `{user_id, username, fingerprint}`; its certificate has `{subject, issuer, serial, not_before, not_after}`. Top-level verification `valid` is true only for signed PDFs when every signature is valid; unsigned PDFs return `no_signature` and an empty signature list.
- `report.pdf` and `notes.txt` begin unsigned. Other Alice-owned PDF fixtures cover valid (`signed.pdf`), modified (`tampered.pdf`), unknown signer (`foreign.pdf`), and two valid signatures (`multi.pdf`). Newly uploaded files begin unsigned.
- Signing increments the canned signature count and does not change PDF bytes. `POST /mock/tamper/{id}` marks a fixture as modified for verification demos.

## Final cleanup

Before final completion, delete `web/mock/`, remove the `tsx` devDependency and `mock`/`mock:smoke` scripts, and remove mock-specific documentation as required by design.md section 9.
