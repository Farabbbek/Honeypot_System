# ============================================
# Stage 1: Build
# ============================================
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci

ARG NEXT_PUBLIC_API_URL=http://159.89.103.231:8000
ARG NEXT_PUBLIC_WS_URL=ws://159.89.103.231:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ENV NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL}

COPY . .

RUN npm run build

# ============================================
# Stage 2: Production runner
# ============================================
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001

RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# Copy next.config.mjs if it exists, otherwise skip
COPY --from=builder /app/next.config.* ./

USER nextjs

EXPOSE 3001

CMD ["npm", "start"]