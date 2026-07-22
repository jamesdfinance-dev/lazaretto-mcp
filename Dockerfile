# Minimal image so MCP directories (e.g. Glama) can build, start, and introspect
# the server. This is a stdio MCP server: the container runs `node index.mjs` and
# speaks MCP over stdin/stdout.
#
# `npm ci` against the committed lockfile, not `npm install`: the image then
# resolves to the exact dependency versions we published and tested, rather than
# whatever is newest at build time. That reproducibility is the whole point of a
# lockfile, and it would be a poor look for a supply-chain scanner to skip it.
FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY index.mjs ./
ENTRYPOINT ["node", "index.mjs"]
