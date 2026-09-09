FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS builder

WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN corepack enable && corepack install
RUN pnpm install --frozen-lockfile --ignore-scripts

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN pnpm run build
RUN pnpm prune --prod --ignore-scripts

FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS runtime

ENV NODE_ENV=production
WORKDIR /app

COPY --chown=node:node --from=builder /workspace/package.json ./package.json
COPY --chown=node:node --from=builder /workspace/node_modules ./node_modules
COPY --chown=node:node --from=builder /workspace/dist ./dist

USER node
EXPOSE 3000
CMD ["node", "dist/delivery/server.js"]
