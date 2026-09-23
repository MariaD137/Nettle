# --- build stage ---
FROM node:25-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# --- runtime stage ---
FROM node:25-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# unzip  — /api/scans extracts uploaded archives with it.
# git    — /api/scans/repo shells out to `git clone` (src/routes/scans.routes.ts).
#          It was missing, so that endpoint failed with ENOENT in every built
#          image regardless of network reachability.
# python3/pip — Semgrep, the real static analysis engine the scanner calls.
RUN apt-get update && apt-get install -y --no-install-recommends unzip git python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages "semgrep==1.65.0" cffi cryptography

COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY bin ./bin

RUN addgroup --system nettle && adduser --system --ingroup nettle nettle

# No NETTLE_DB_PATH and no writable data volume.
#
# This image is production-only (NODE_ENV=production above), and in production
# the application requires DATABASE_URL and refuses to start without it — see
# assertProductionPersistence() in src/db/index.ts. SQLite is unreachable here
# by construction, so a writable /data directory would be unused surface
# rather than useful storage. Application state lives in RDS; see
# docs/DATABASE.md.
#
# /app therefore stays root-owned and read-only to the application, which runs
# as the unprivileged `nettle` user. The only writable location the process
# needs is /tmp, used for scan extraction workspaces.
#
# DATABASE_URL is injected by App Runner from Secrets Manager
# (infra/lib/api-stack.ts). It is never baked into the image.

USER nettle

EXPOSE 8080
CMD ["node", "dist/index.js"]
