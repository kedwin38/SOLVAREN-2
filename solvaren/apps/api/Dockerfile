# SOLVAREN API — production image.
#
# Multi-stage: the runtime image carries no compiler, no test suite and no dev
# dependencies. Migrations travel with the image so Railway's pre-deploy command can
# apply them.

# ---- Build ------------------------------------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /repo

RUN corepack enable

# pnpm refuses to remove a modules directory without a TTY in a container:
# ERR_PNLM_ABORTED_REMOVE_MODULES_DIR_NO_TTY. CI=true is pnpm's non-interactive switch.
ENV CI=true

# Manifests first, so editing source does not invalidate the dependency layer.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY packages/core/package.json packages/core/
COPY packages/daraja/package.json packages/daraja/
COPY packages/storage/package.json packages/storage/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/

RUN pnpm install --frozen-lockfile --ignore-scripts

COPY tsconfig.base.json ./
COPY packages packages
COPY apps/api apps/api

# The packages compile before the app (the app resolves their sources at build time).
RUN pnpm --filter @solvaren/core build \
 && pnpm --filter @solvaren/daraja build \
 && pnpm --filter @solvaren/storage build \
 && pnpm --filter @solvaren/api build

RUN pnpm install --frozen-lockfile --prod --ignore-scripts

# ---- Runtime ----------------------------------------------------------------
FROM node:22-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production

# Run as a non-root user: a process that cannot write to its own image cannot be made
# to persist anything by an attacker who reaches code execution.
RUN useradd --system --uid 10001 --home /app solvaren

COPY --from=build /repo/node_modules ./node_modules
COPY --from=build /repo/package.json ./package.json
COPY --from=build /repo/pnpm-workspace.yaml ./pnpm-workspace.yaml

COPY --from=build /repo/packages/core/package.json ./packages/core/package.json
COPY --from=build /repo/packages/core/dist ./packages/core/dist
COPY --from=build /repo/packages/core/node_modules ./packages/core/node_modules

COPY --from=build /repo/packages/daraja/package.json ./packages/daraja/package.json
COPY --from=build /repo/packages/daraja/dist ./packages/daraja/dist
COPY --from=build /repo/packages/daraja/node_modules ./packages/daraja/node_modules

COPY --from=build /repo/packages/storage/package.json ./packages/storage/package.json
COPY --from=build /repo/packages/storage/dist ./packages/storage/dist
COPY --from=build /repo/packages/storage/node_modules ./packages/storage/node_modules

COPY --from=build /repo/apps/api/package.json ./apps/api/package.json
COPY --from=build /repo/apps/api/dist ./apps/api/dist
COPY --from=build /repo/apps/api/node_modules ./apps/api/node_modules

# Migrations and the runner travel with the image (pre-deploy command).
COPY db/migrations ./db/migrations
COPY scripts/migrate.mjs ./scripts/migrate.mjs

USER solvaren

EXPOSE 8080

CMD ["node", "--enable-source-maps", "apps/api/dist/server.js"]
