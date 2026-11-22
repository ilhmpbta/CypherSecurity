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

## Final cleanup

Before final completion, delete `web/mock/`, remove the `tsx` devDependency and `mock`/`mock:smoke` scripts, and remove mock-specific documentation as required by design.md section 9.
