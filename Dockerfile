# Minimal image so MCP directories (e.g. Glama) can build, start, and introspect
# the server. This is a stdio MCP server: the container runs `node index.mjs` and
# speaks MCP over stdin/stdout.
FROM node:22-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY index.mjs ./
ENTRYPOINT ["node", "index.mjs"]
