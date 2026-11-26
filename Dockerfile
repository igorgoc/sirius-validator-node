FROM node:20-bookworm-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Node dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy application source
COPY . .

# Ensure data directories exist and drop privileges to non-root node user
RUN mkdir -p /app/data/drives /app/data/logs \
    && chown -R node:node /app \
    && chmod 700 /app/data

# Environment configuration
ENV NODE_ENV=production
ENV VM_PORT=5051
ENV SIRIUS_VM_BIND_HOST=0.0.0.0
ENV DATA_DIR=/app/data
ENV CONTRACTS_DIR=/app/contracts

USER node

EXPOSE 5051

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD node scripts/healthcheck.js || exit 1

CMD ["node", "executor/grpc_vm_server.js"]
