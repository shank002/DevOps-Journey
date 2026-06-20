#Stage 1: Install Dependencies
FROM node:20-alpine3.19 AS deps
WORKDIR /app
COPY package*.json ./
COPY app/package*.json ./
#RUN npm ci --only=production
RUN npm install
RUN npm ci --omit=dev

#Stage 2: Runtime - Clean minimal image
FROM node:20-alpine3.19
WORKDIR /app

#Creating a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

#Copy only what we need from builders
COPY --chown=appuser:appgroup --from=deps /app/node_modules ./node_modules
COPY --chown=appuser:appgroup app/server.js ./

#SWITCH to non-root user
USER appuser

EXPOSE 3000

CMD ["node", "server.js"]


