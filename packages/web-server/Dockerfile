FROM node:20-slim

WORKDIR /app

# Copy workspace root config
COPY package.json tsconfig.base.json ./

# Copy all package manifests so npm workspaces resolves correctly
COPY packages/shared/package.json ./packages/shared/
COPY packages/web-server/package.json ./packages/web-server/

# Install all workspace dependencies
RUN npm install

# Copy source for shared package and build it
COPY packages/shared/ ./packages/shared/
RUN npm run build --workspace=packages/shared

# Copy web-server source and build
COPY packages/web-server/ ./packages/web-server/
RUN npm run build --workspace=packages/web-server

EXPOSE 3000

CMD ["node", "packages/web-server/dist/index.js"]
