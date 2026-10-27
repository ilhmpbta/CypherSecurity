# CypherSecurity

A web application for storing criminal-case evidence. Every file is stream-encrypted with AES-256-GCM at rest. Only the authenticated investigator who uploaded a file can download it, and the download verifies integrity before returning plaintext.

Built for the KI (Keamanan Informasi) course assignment: build a web app that protects stored personal data, then measure AES, DES, and RC4 in practice.

---

## Team

| StudentID | Handle | Role | Area |
|---|---|---|---|
| 5025241111 | [Hanif Aqil Janardana](https://github.com/Haaqill) | Crypto | Production AEAD, KeyManager, academic ciphers |
| 5025241152 | [Bintang Ilham Pabeta](https://github.com/ilhmpbta) | Backend | HTTP API, auth, file service, storage |
| 5025241162 | [Felix Aldorino](https://github.com/NewGenome) | Frontend | `web/` scaffold, auth pages, upload/list/records UI |

---

## What this is

An investigation team is currently conducting an investigation on a criminal case. The team needs to save the evidence in a system that is safe. Thus they need an application that can save files with encryption to prevent data leak.


Files are classified under GDPR Article 4(1) (personal data) and UU PDP Law No. 27/2022 (personal data, general and specific categories). ID card images, uploaded documents, personal records, and video files all qualify.

---

## Running locally

### Prerequisites

- Go 1.27 or newer
- Docker Desktop (for Postgres)
- Node.js 20 or newer (for the frontend build)
- `openssl` (for the KEK)

### One-time setup

```bash
cp .env.example .env
```

Edit `.env` and set two values:

```bash
# The server refuses to start without a valid 32-byte KEK.
CYPHER_KEK=<output of: openssl rand -base64 32>

# Required for local HTTP dev otherwise browsers discard the session cookie and login fails.
CYPHER_SECURE_COOKIES=false
```

Everything else in `.env.example` has working defaults.

### Start the database

```bash
docker compose up -d postgres
```

Wait ~5 seconds. `docker compose ps` should show `healthy`.

### Build the frontend

The frontend is served from the Go binary via `go:embed`. The build step
produces `web/dist/`:

```bash
cd web
npm install
npm run build
cd ..
```

### Start the server

```bash
go run ./cmd/server
```

Expected output:

```
cyphersecurity: listening on :8080
```

Open <http://localhost:8080>. Migrations run automatically on startup.

### Verify

```bash
curl -s localhost:8080/healthz
# {"status":"ok"}
```

---

## Benchmark report

The full benchmark harness lives in [`benchmark/`](benchmark/). The CSV
outputs of every run are committed under
[`benchmark/results/`](benchmark/results/).

### What was measured

Pure-crypto benchmarks only. Each scheme encrypts and decrypts a fixed fixture in-process, the timing reflects the cipher itself rather than the storage or network layers.

Five fixtures, sized to match the file types the app accepts:

| Fixture | Size |
|---|---|
| id_image | 200 KiB |
| doc | 1 MiB |
| pdf | 2 MiB |
| xls | 10 MiB |
| video | 100 MiB |

Five schemes, chosen from the crypto/academic package plus the production package:

- AES-256-CBC (PKCS#7)
- AES-256-CTR
- AES-256-GCM (production, streaming, 1 MiB chunks)
- RC4
- DES-CBC (PKCS#7)

Metrics recorded per (algorithm, mode, file, op): `ns/op`, `MB/s`, ciphertext size, and whether the scheme can detect tampering.

### Environment

All results below were produced on:

- **CPU**: AMD Ryzen 7 7445HS with Radeon 740M Graphics
- **RAM**: 16 GB (15.23 GiB usable)
- **OS**: Windows 11, MSYS2 / MSYS_NT-10.0-26200
- **Go**: `go1.27.3 windows/amd64`

The CPU has AES hardware acceleration (AES-NI). Go's standard library uses it automatically on supporting CPUs; the AES results below include that acceleration. RC4 and DES have no such acceleration path in the Go stdlib.

### Reproducing

```bash
go test -bench=. -benchmem -count=5 -run '^$' ./benchmark/...
```

The command takes about 6 minutes on the hardware above (the 100 MiB fixtures dominate). It writes `benchmark/results/<UTC-timestamp>.csv`. The `-run '^$'` flag skips the regular tests so only benchmarks run.

To regenerate the fixtures from scratch (they're deterministic, so they should be byte-identical):

```bash
rm -rf benchmark/files/*.bin
go test -run TestFixturesExist ./benchmark/...
```

### Encryption throughput

Mean plaintext throughput in MB/s, aggregated over 5 runs per cell.
**Bold** = fastest in the row. _Italic_ = slowest.

| File | AES-CBC | AES-CTR | AES-GCM | RC4 | DES-CBC |
|---|---:|---:|---:|---:|---:|
| id_image | 625.04 | **2927.69** | 780.07 | 515.32 | _92.26_ |
| doc | 674.49 | **3844.40** | 1255.98 | 562.29 | _97.47_ |
| pdf | 713.87 | **2965.97** | 1307.05 | 607.93 | _93.46_ |
| xls | 755.48 | **3558.22** | 1418.65 | 610.74 | _95.24_ |
| video | 744.41 | **4174.61** | 1719.10 | 621.25 | _96.31_ |

### Decryption throughput

| File | AES-CBC | AES-CTR | AES-GCM | RC4 | DES-CBC |
|---|---:|---:|---:|---:|---:|
| id_image | 1137.90 | **3157.40** | 776.28 | 509.43 | _98.86_ |
| doc | 1096.09 | **3043.74** | 1998.83 | 553.35 | _96.18_ |
| pdf | 1368.58 | **3796.37** | 1880.15 | 613.23 | _97.72_ |
| xls | 1454.77 | **3786.74** | 2292.34 | 617.92 | _99.08_ |
| video | 1489.22 | **4352.54** | 3021.77 | 625.55 | _97.89_ |

### 100 MiB video, one-shot

The five-sample aggregate above and the isolated one-shot run (`-benchtime=1x`) . The one-shot shows cost:

| Scheme | Encrypt | Decrypt | Ciphertext |
|---|---:|---:|---:|
| AES-256-CBC | 141.30 ms | 91.57 ms | 104,857,632 B |
| AES-256-CTR | 25.45 ms | 24.73 ms | 104,857,616 B |
| AES-256-GCM | 69.89 ms | 47.56 ms | 104,859,212 B |
| RC4 | 222.73 ms | 167.87 ms | 104,857,600 B |
| DES-CBC | 1451.37 ms | 1614.27 ms | 104,857,616 B |

### Ciphertext overhead

Exact sizes, plus the source of the overhead.

| Scheme | id_image (+B) | doc (+B) | pdf (+B) | xls (+B) | video (+B) | Cause |
|---|---:|---:|---:|---:|---:|---|
| RC4 | 0 | 0 | 0 | 0 | 0 | Stream cipher, no IV, no tag |
| AES-CTR | 16 | 16 | 16 | 16 | 16 | IV |
| DES-CBC | 16 | 16 | 16 | 16 | 16 | IV (8) + PKCS#7 pad (8, all fixtures block-aligned) |
| AES-CBC | 32 | 32 | 32 | 32 | 32 | IV (16) + PKCS#7 pad (16) |
| AES-GCM | 28 | 28 | 44 | 172 | 1612 | Base nonce (12) + tag (16 × ⌈n / 1 MiB⌉) |

Non-block-aligned inputs would change the AES-CBC and DES-CBC columns by
up to 15 and 7 bytes respectively, but the fixtures here all land on
block boundaries so the padding is a full block.

### Tamper detection

The `tamper_detected` column in the CSV is `true` for exactly one scheme:

| Scheme | Detects tampering? |
|---|---|
| AES-256-GCM | **yes** |
| AES-256-CBC | no |
| AES-256-CTR | no |
| RC4 | no |
| DES-CBC | no |

CBC and DES-CBC will often fail to decrypt when tampered (padding check),
but a successful decryption is not proof of integrity. CTR and RC4 are
malleable: flipping a ciphertext byte flips the corresponding plaintext
byte and the operation still "succeeds." Only GCM, with its 16-byte
authentication tag per chunk, both decrypts and authenticates.

The harness verifies this with two tests: `TestTamperDetectedGCM` flips a
byte in a sealed GCM stream and asserts `Read` returns an error;
`TestTamperSilentCBC` flips a byte in a CBC ciphertext and asserts
`DecryptAES256CBC` returns no error (silent corruption).

### Reading the numbers

**AES-CTR is fastest across all fixtures.** It exceeds AES-CBC by 4.71× (encrypt) / 2.60× (decrypt) on the 10 MiB XLS fixture, and 5.61× / 2.92× on the video aggregate. This is larger than the textbook-expected 1.2–1.8× ratio; the discrepancy is in this implementation and this CPU, not a general claim about the two modes.

**AES-GCM is faster than AES-CBC despite doing more work.** For the XLS fixture, GCM reports 1418.65 vs 755.48 MB/s encrypt and 2292.34 vs 1454.77 MB/s decrypt. GCM adds GHASH (authentication) and allocates ciphertext as a buffer, but is still faster than CBC's padding and block-by-block path on this hardware. GCM is slower than CTR by 2.51× (encrypt) / 1.65× (decrypt) on XLS, and 2.43× / 1.44× on video. The gap reflects GHASH and buffer copies, but the harness does not isolate GHASH from buffer management, so this measurement alone cannot say which dominates.

**RC4 is not faster than AES on this machine.** On the 100 MiB video, RC4 encrypts at 480.58 MB/s aggregate (one-shot: 222.73 ms), against AES-CTR at 4138.24 MB/s (25.45 ms). AES-NI hardware acceleration makes AES the practical winner by a wide margin. RC4's only advantage is zero ciphertext overhead — it produces exactly the plaintext's bytes — which is not a security property and comes at the cost of no integrity protection at all.

**DES-CBC is 10–18× slower than AES-CBC here,** in addition to its
56-bit effective key length and NIST withdrawal in 2005. It is included
strictly as a pedagogical comparison.

### Design choices this data informed

The production stack uses **AES-256-GCM** for every stored file ([`internal/crypto/production/aead.go`](internal/crypto/production/aead.go)). Three properties of the measured data drove that decision:

1. **It authenticates.** Only GCM detects ciphertext tampering. For ID card images, personal records, and uploaded documents — which the application classifies as personal data under GDPR and UU PDP — returning unauthenticated plaintext on a modified ciphertext is not defensible. CBC, CTR, and RC4 all fail this requirement.
2. **It is fast enough for streaming.** On the 100 MiB video fixture, GCM encrypts in 69.89 ms and decrypts in 47.56 ms well inside the server's 120 s `WriteTimeout` for streaming responses, and faster than CBC in both directions on this hardware.
3. **Overhead is bounded and predictable.** The 1 MiB chunk size adds 16 bytes of tag per chunk; for a 100 MiB file that is 1612 bytes total, a ratio of 1.00001537. The 12-byte base nonce lives inside the ciphertext blob, not in the database row, so there is nothing to lose if the metadata table is dumped in isolation.

Per-file keys are generated on upload and wrapped by a KEK ([`internal/crypto/production/keymanager.go`](internal/crypto/production/keymanager.go)), so rotating the KEK requires re-wrapping 32-byte DEKs, not re-encrypting user files.

---

## Where things live

| What | Where |
|---|---|
| Production AEAD | `internal/crypto/production/aead.go` |
| Production KEK/DEK | `internal/crypto/production/keymanager.go` |
| Academic AES/DES/RC4 | `internal/crypto/academic/` |
| Benchmark harness | `benchmark/harness.go` |
| Benchmark entry points | `benchmark/benchmarks_test.go` |
| CSV writer | `benchmark/report.go` |
| Benchmark results | `benchmark/results/*.csv` |
| File service | `internal/files/service.go` |
| Storage layer | `internal/storage/` |
| HTTP API | `internal/httpapi/` |
| Frontend | `web/` |
