# --- build stage ---
FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# --- runtime stage ---
FROM node:22-slim AS runtime
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

# The database path is explicit, and lives outside /app.
#
# It previously defaulted to process.cwd()/nettle.db — that is /app, which is
# owned by root so that the application cannot modify its own code. A non-root
# process cannot create a file there, and src/db/index.ts opens the database at
# import time, so the container crashed on startup before it could serve a
# single request.
#
# /data is the one writable location, owned by the run user and nothing else
# (mode 0750, not a blanket chmod 777). /app stays root-owned and read-only to
# the application. Scan workspaces continue to use /tmp.
ENV NETTLE_DB_PATH=/data/nettle.db
RUN mkdir -p /data && chown nettle:nettle /data && chmod 750 /data
VOLUME ["/data"]

USER nettle

EXPOSE 8080
CMD ["node", "dist/index.js"]
