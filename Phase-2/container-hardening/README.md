# container-hardening

A before-and-after Dockerfile security audit. Built as part of Phase 2 (Docker & Containers) of a DevSecOps learning roadmap. The goal: take a deliberately insecure Node.js container, scan it with Trivy, identify every finding, and harden it — demonstrating the difference in attack surface between the two versions.

---

## Project structure

```
container-hardening/
├── app/
│   ├── server.js          # Simple Express app
│   ├── package.json
│   └── .env               # Present in build context intentionally (to demonstrate the leak)
├── Dockerfile.vulnerable  # Baseline — multiple security issues
├── Dockerfile.hardened    # Fixed version
├── .dockerignore          # Added during hardening
├── reports/
│   ├── trivy-vulnerable-node.report
│   └── trivy-hardened-node.report
└── README.md
```

---

## What the app does

A minimal Express.js server that responds on port 3000. The application itself is intentionally trivial — the point of this project is the container, not the code.

```js
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello from container'));
app.listen(3000, '0.0.0.0');
```

---

## Dockerfile.vulnerable — the five problems

Each issue is labeled in the file. Here's what each one means and why it matters:

**Issue 1 — `FROM node:latest`**
`:latest` is not a fixed reference. A rebuild six months later may pull a completely different image with new CVEs. The vulnerable image resolved to `node:latest` on Debian 13.5 (bookworm), which carries a massive OS-level attack surface.

**Issue 2 — `COPY . .` with no `.dockerignore`**
The entire build context is sent to the Docker daemon, including `.env`, which contains a database URL and an API key. These get baked into the image layer and are visible via `trivy image --scanners secret` and `docker history --no-trunc`.

**Issue 3 — `RUN npm install` (all dependencies)**
Installs `devDependencies` alongside production packages. Dev tools have no business in a production image — they expand the attack surface and add unnecessary CVEs.

**Issue 4 — `ENV DATABASE_URL=postgres://admin:secret@db`**
Secrets in `ENV` are stored in image metadata. Visible via `docker inspect <container>` and readable from `/proc/<pid>/environ` on the host. Anyone with Docker socket access can read them.

**Issue 5 — No `USER` directive (runs as root)**
Without an explicit `USER`, the container process runs as UID 0. If the app has a vulnerability that gives an attacker code execution, they get a root shell. No privilege boundary.

---

## Trivy scan — vulnerable image

**Image:** `nodeapp:vuln` (Debian 13.5 base via `node:latest`)

```
Total OS vulnerabilities:  1779
  CRITICAL:  28
  HIGH:      186
  MEDIUM:    495
  LOW:       984
  UNKNOWN:   86

Node package vulnerabilities: 5
  HIGH:    1
  MEDIUM:  2
  LOW:     2
```

**Notable CRITICAL findings (OS layer):**

| Package | CVE | Description |
|---|---|---|
| `libmariadb3`, `libmariadb-dev` | CVE-2026-44170 | MariaDB — arbitrary code execution |
| `libopenexr-3-1-30`, `libopenexr-dev` | CVE-2026-42216 | OpenEXR — information disclosure and DoS |
| `libperl5.40`, `perl`, `perl-base` | CVE-2026-42496 | perl-archive-tar — path traversal |
| `libraw23t64` | CVE-2026-20884 | LibRaw — arbitrary code execution via integer overflow |
| `linux-libc-dev` | CVE-2026-43185 | Kernel signedness bug (ksmbd) |

The root cause of all 28 CRITICAL findings is the base image choice: `node:latest` is built on full Debian, which ships hundreds of packages the application never uses — MariaDB client libraries, Perl, OpenEXR, LibRaw — every one of them a potential exploit path.

---

## Dockerfile.hardened — the fixes

```dockerfile
# Stage 1: install production dependencies only
FROM node:20-alpine3.19 AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Stage 2: clean runtime image
FROM node:20-alpine3.19
WORKDIR /app

RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup

COPY --chown=appuser:appgroup --from=deps /app/node_modules ./node_modules
COPY --chown=appuser:appgroup app/server.js ./

USER appuser

EXPOSE 3000
CMD ["node", "server.js"]
```

**What each change does:**

| Fix | How | Why |
|---|---|---|
| Pin base image | `node:20-alpine3.19` | Fixed tag, Alpine base — minimal OS packages |
| Multi-stage build | Separate `deps` and runtime stages | Build tools never reach the final image |
| Production deps only | `npm ci --only=production` | Removes devDependencies and their CVEs |
| `.dockerignore` | Excludes `.env`, `.git`, `*.log` | Prevents secrets from entering the build context |
| Non-root user | `adduser` + `USER appuser` | Process runs as UID 100, not UID 0 |
| `--chown` on COPY | Files owned by `appuser` | No root-owned files the non-root process can't read |

---

## Trivy scan — hardened image

**Image:** `nodeapp:hardened` (Alpine 3.19.4 base)

```
Total OS vulnerabilities:  20
  CRITICAL:  0
  HIGH:      4
  MEDIUM:    7
  LOW:       9
  UNKNOWN:   0

Node package vulnerabilities: 16
  HIGH:    11
  MEDIUM:   3
  LOW:      2
  CRITICAL: 0
```

**Residual HIGH findings (OS layer — 4 total):**

| Package | CVE | Note |
|---|---|---|
| `musl`, `musl-utils` | CVE-2025-26519 | Alpine's C library — no fix available at time of scan |

**Residual HIGH findings (node_modules — selected):**

| Package | CVE | Fixed in |
|---|---|---|
| `cross-spawn` | CVE-2024-21538 | 7.0.5 / 6.0.6 |
| `glob` | CVE-2025-64756 | 11.1.0 / 10.5.0 |
| `minimatch` | CVE-2026-26996 | Multiple versions — check lockfile |

The node_modules findings are transitive dependencies pulled in by Express. The `musl` finding has no upstream fix available. These are tracked, not ignored — in a production pipeline, they would be exceptions in the scanner config with a documented rationale and a review date.

---

## Before vs after

| Metric | Vulnerable | Hardened |
|---|---|---|
| Base OS | Debian 13.5 (full) | Alpine 3.19.4 (minimal) |
| Total vulnerabilities | 1784 | 36 |
| CRITICAL | 28 | 0 |
| HIGH (OS) | 186 | 4 |
| Runs as root | Yes (UID 0) | No (UID 100) |
| `.env` in image | Yes | No |
| Secrets in ENV | Yes | No |

A 98% reduction in total CVEs. CRITICAL findings eliminated to zero. No secrets baked into any layer.

---

## Verification commands

```bash
# Confirm non-root execution
docker run --rm nodeapp:hardened id
# uid=100(appuser) gid=101(appgroup) groups=101(appgroup)

# Confirm .env is not in the image
docker run --rm nodeapp:hardened cat /app/.env
# cat: /app/.env: No such file or directory

# Confirm no secrets in layers (run with secrets scanner)
trivy image --scanners secret nodeapp:hardened
# No secrets found.

# Image size comparison
docker images | grep nodeapp
# nodeapp  vulnerable  ~1.1GB
# nodeapp  hardened    ~175MB
```

---

## What a production pipeline adds

This project hardened the image manually. In a real DevSecOps workflow, this scan runs automatically in CI before any image is deployed:

- Trivy runs as a GitHub Actions step on every pull request
- A CRITICAL or HIGH finding above a threshold fails the build
- The developer sees the findings before the image ever reaches staging
- Approved exceptions are documented in the scanner config, not silently ignored

That pipeline is built in Phase 3 of this roadmap.

---

## Key takeaway

The base image is the most consequential security decision in a Dockerfile. `node:latest` on Debian ships MariaDB client libraries, Perl, OpenEXR, and LibRaw — none of which a Node.js web server needs, all of which are CVE surface. Switching to `node:20-alpine3.19` and removing unused packages eliminated 28 CRITICAL vulnerabilities before touching a single line of application code.
