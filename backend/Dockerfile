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

# unzip is required at runtime — /api/scans shells out to it to extract uploads
RUN apt-get update && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY bin ./bin

RUN addgroup --system nettle && adduser --system --ingroup nettle nettle
USER nettle

EXPOSE 8080
CMD ["node", "dist/index.js"]
