# Deployment Guide

## Requirements
- Bun >=1.1.2
- SQLite (file-based)

## Environment Variables
```
JWT_SECRET=your-super-secret-key-min-32-chars
JWT_EXPIRES_IN=24h
NODE_ENV=production
LOG_LEVEL=INFO
LOG_DIR=./logs
DB_PATH=./auth.db
```

## Production Setup
1. **Build**:
   ```
   bun run build
   ```

2. **Run**:
   ```
   bun run dist/index.js
   # or
   bun --prod src/index.ts
   ```

3. **Database**:
   - SQLite: `auth.db` auto-created
   - Custom adapter: configure in code

4. **Logging**:
   - Production: file-only, JSON
   - Rotation: 50MB x 10 files

5. **Scaling**:
   - Stateless (JWT)
   - Shared DB for sessions
   - Redis for rate limit (custom)

## Docker
```dockerfile
FROM oven/bun:latest
WORKDIR /app
COPY . .
RUN bun install --production
RUN bun run build
CMD ["bun", "run", "dist/index.js"]
```

## Monitoring
- Logs: rotate, centralize (ELK)
- Metrics: Prometheus endpoints (custom)
- Health: `/health` endpoint (add)

See `package.json` scripts.