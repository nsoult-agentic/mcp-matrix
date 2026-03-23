# mcp-matrix — Secure Matrix messaging MCP server
# Multi-stage build: install deps -> production image

# -- Build stage --
FROM oven/bun:1.3.10-alpine AS build

WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --production

# -- Production stage --
FROM oven/bun:1.3.10-alpine

WORKDIR /app

# Copy only production artifacts
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/

# Non-root user for defense-in-depth
USER bun

EXPOSE 8903

# Auto-link ghcr.io package to repo
LABEL org.opencontainers.image.source=https://github.com/nsoult-agentic/mcp_matrix

CMD ["bun", "run", "src/http.ts"]
