FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080 DATA_DIR=/data DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app /data && chown node:node /app /data
WORKDIR /app
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.mjs"]

FROM runtime AS test
COPY --chown=node:node test ./test
COPY --chown=node:node scripts ./scripts
ENV DATA_DIR=/tmp/test-data
CMD ["node", "--test"]
