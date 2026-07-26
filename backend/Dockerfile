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

# unzip is required at runtime — /api/scans shells out to it to extract uploads.
# python3/pip are required to install and run Semgrep, the real static
# analysis engine the scanner shells out to (see src/scanner/semgrepScanner.ts).
RUN apt-get update && apt-get install -y --no-install-recommends unzip python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages semgrep cffi cryptography

COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY bin ./bin

RUN addgroup --system nettle && adduser --system --ingroup nettle nettle
USER nettle

EXPOSE 8080
CMD ["node", "dist/index.js"]
