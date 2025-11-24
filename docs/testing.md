# Testing Guide

Comprehensive test suite with 100% coverage for core features.

## Running Tests

```bash
# All tests
bun test --preload tests/setup.ts

# Coverage
bun test --coverage --preload tests/setup.ts

# Specific files
bun test tests/auth.test.ts
bun test tests/oauth.test.ts

# Watch mode
bun test --watch

# Debug
bun test --timeout=0 --inspect
```

## Test Structure

- `tests/base-controller.test.ts`: CRUD, queries
- `tests/oauth.test.ts`: OAuth flows
- `tests/schema-extension.test.ts`: Schema extensions
- `tests/bit-data.test.ts`: BIT type handling
- `tests/services/auth.test.ts`: AuthService
- `tests/services/jwt.test.ts`: JWT, DPoP

Preload: `tests/setup.ts` initializes DB.

## Writing Tests

Use Bun test runner, SQLite in-memory.

Example:
```typescript
import { test, expect } from 'bun:test';
import { DatabaseInitializer } from '../src/database/database-initializer';

test('AuthService register', async () => {
  const db = new Database(':memory:');
  const initializer = new DatabaseInitializer({ database: db });
  await initializer.initialize();
  
  // Test logic
});
```

CI: `.github/workflows/test.yml`