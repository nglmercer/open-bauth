# Database Adapter System

This documentation explains how to use the database adapter system of the library, which provides complete flexibility to work with different types of databases.

## Overview

The adapter system allows:
- Use Bun SQL database by default
- Integrate custom adapters for other databases
- Maintain compatibility with existing code
- Extend functionality according to specific needs

## Basic Usage

### 1. Using Default Adapter (Bun SQL)

```typescript
import { BaseController } from "./src/database/base-controller";
import { SQL } from "bun";

const db = SQL("my-database.sqlite");
const userController = new BaseController("users", {
  database: db,
  isSQLite: true
});
```

### 2. Using Custom Adapter

```typescript
import { BaseController } from "./src/database/base-controller";
import { SimpleCustomAdapter } from "./examples/custom-adapter-example";

const customAdapter = new SimpleCustomAdapter({
  connectionString: "custom://localhost"
});

const customController = new BaseController("users", {
  adapter: customAdapter
});
```

## Creating a Custom Adapter

### Basic Interface

Every adapter must implement the `IDatabaseAdapter` interface:

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

### Complete Example

```typescript
import { IDatabaseAdapter, DatabaseConnection } from "./src/database/adapter";

export class MyCustomAdapter implements IDatabaseAdapter {
  private connection: DatabaseConnection;
  private config: any;

  constructor(config: any) {
    this.config = config;
    this.connection = this.createConnection();
  }

  async initialize(): Promise<void> {
    console.log('Adapter initialized');
  }

  async close(): Promise<void> {
    console.log('Adapter closed');
  }

  isConnected(): boolean {
    return true;
  }

  getConnection(): DatabaseConnection {
    return this.connection;
  }

  getDatabaseType() {
    return {
      isSQLite: false,
      isSQLServer: false,
      isPostgreSQL
