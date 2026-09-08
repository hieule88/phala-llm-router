# Note-watcher: scans the Miden chain for P2ID payments to the gateway
# account and reports them to auth-service's onchain webhook.
#
# The SDK's node build comes from the private Gitea npm registry (see
# .npmrc). If the registry requires auth for reads, pass a token:
#   docker compose build --build-arg GITEA_NPM_TOKEN=...
FROM node:22-slim

WORKDIR /app

# ARG (not ENV): build args are visible to RUN in this stage, which is
# all npm needs to expand ${GITEA_NPM_TOKEN} in .npmrc. An ENV would
# bake the token into the image metadata and every container spawned
# from it. (`docker history` still shows ARG values — for a fully clean
# image use RUN --mount=type=secret instead.)
ARG GITEA_NPM_TOKEN=

COPY package.json .npmrc ./
RUN npm install --omit=dev

COPY src ./src
COPY scripts ./scripts

# Cursor + report bookkeeping live here — MUST be a volume: losing it
# re-scans (harmless, the server dedups) but forgets dead-letters.
VOLUME /state

CMD ["node", "src/watcher.mjs"]
