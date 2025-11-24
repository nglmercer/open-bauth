# Database Adapter System

This documentation explains the library's database adapter system, providing full flexibility for different databases.

## Overview

The adapter system allows:
- Default Bun SQL database
- Custom adapters for other DBs
- Existing code compatibility
- Functionality extension

## Basic Usage

### 1. Default Adapter (Bun SQL)

```typescript
import { BaseController } from "open-bauth/src/database/base-controller";
import { Database } from "bun:sqlite";

const db = new Database("my-database.sqlite");
const userController = new BaseController("users", {
  database: db,
  isSQLite: true
});

// All methods work the same
const users = await userController.findAll();
```

### 2. Custom Adapter

```typescript
import { BaseController } from "open-bauth/src/database/base-controller";
import { JsonFileAdapter } from "./examples/custom-adapter-example";

const adapter = new JsonFileAdapter({ filePath: './data.json' });
await adapter.initialize();

const controller = new BaseController("users", { adapter });
const users = await controller.findAll();
```

## Creating Custom Adapter

### Interface

```typescript
interface IDatabaseAdapter {
  getConnection(): DatabaseConnection;
  initialize(): Promise<void>;
  close(): Promise<void>;
  isConnected(): boolean;
  getConfig(): any;
  getDatabaseType(): DatabaseType;
  getSqlHelpers(): SqlHelpers;
}
```

### Full Example: JsonFileAdapter

See [`examples/custom-adapter-example.ts`](examples/custom-adapter-example.ts:11) for JsonFileAdapter and MemoryAdapter with real methods (getCurrentCounter, incrementCounter).

### BaseController Options

```typescript
interface BaseControllerOptions {
  database?: Database;
  adapter?: IDatabaseAdapter;
  schemas?: SchemaCollection;
  isSQLite?: boolean;
}
```

## Best Practices

### Error Handling
```typescript
class RobustAdapter implements IDatabaseAdapter {
  async initialize(): Promise<void> {
    let retries = 3;
    while (retries > 0) {
      try {
        await this.connect();
        break;
      } catch (error) {
        retries--;
        if (retries === 0) throw error;
        await new Promise(r => setTimeout(r, 1000));
      }
    }
  }
}
```

### Connection Pool
Use pools for high concurrency.

### Logging & Metrics
Track query count, latency.

## Complete Example
```typescript
const adapter = new JsonFileAdapter({ filePath: './data.json' });
await adapter.initialize();

const controller = new BaseController("users", { adapter });
const users = await controller.findAll();

await adapter.close();
```

This system provides flexibility while maintaining API consistency.
