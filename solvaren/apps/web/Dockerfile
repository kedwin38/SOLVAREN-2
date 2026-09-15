# SOLVAREN console — static hosting on nginx.
#
# The hardened headers live here (the API's CSP applies to API responses; the console
# needs its own). scripts/check-invariants.sh is intentionally quiet about this file —
# the console's CSP must allow its own hashed assets and nothing else.

FROM node:22-bookworm-slim AS build
WORKDIR /repo

RUN corepack enable
ENV CI=true

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY packages/core/package.json packages/core/
COPY packages/daraja/package.json packages/daraja/
COPY packages/storage/package.json packages/storage/
COPY apps/web/package.json apps/web/

RUN pnpm install --frozen-lockfile --ignore-scripts

COPY tsconfig.base.json ./
COPY packages/core packages/core
COPY apps/web apps/web

ARG VITE_API_BASE_URL
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

RUN pnpm --filter @solvaren/web build

# ---- Runtime ----------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /repo/apps/web/dist /usr/share/nginx/html

EXPOSE 80
