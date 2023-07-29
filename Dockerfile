# ---- Base Node ----
FROM node:20-alpine AS base
# Set working directory
WORKDIR /app
# Copy project file
COPY package*.json ./

# ---- Dependencies ----
FROM base AS dependencies
# Install production dependencies
RUN npm ci --omit=dev

# ---- Copy Files/Build ----
FROM base AS build
WORKDIR /app
COPY . /app
# Build the application
RUN npm install

# --- Release with Alpine ----
FROM node:20-alpine AS release
# Set working directory
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=build /app .
# Expose the listening port
EXPOSE 3000
CMD [ "node", "index.mjs" ]
