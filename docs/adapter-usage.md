# Database Adapter Usage Guide

This guide covers the database adapter system that allows you to use custom database implementations while maintaining the same API.

## 📋 Table of Contents

- [Overview](#overview)
- [Core Interface](#core-interface)
- [Built-in Adapters](#built-in-adapters)
- [Creating Custom Adapters](#creating-custom-adapters)
- [Adapter Factory](#adapter-factory)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)

## 🌟 Overview

The adapter system provides a unified interface for different database backends while maintaining consistent API behavior across all implementations.

### Key Benefits

- **Database Agnostic**: Support for SQLite, PostgreSQL, MySQL, and custom implementations
- **Consistent API**: Same methods regardless of underlying database
- **Easy Migration**: Switch between databases without code changes
- **Extensible**: Create custom adapters for specialized requirements
- **Type Safety**: Full TypeScript support for all adapters

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                      │
└─────────────────────┬───────────────────────────────────┘
                      │ BaseController API
┌─────────────────────▼───────────────────────────────────┐
│              Adapter Interface Layer                    │
│  IDatabaseAdapter                                   │
│  - getConnection()                                   │
│  - initialize()                                      │
│  - close()                                          │
│  - isConnected()                                     │
│  - getDatabaseType()                                 │
│  - getSqlHelpers()                                  │
└─────────────────────┬───────────────────────────────────┘
                      │ Database Implementation
┌─────────────────────▼───────────────────────────────────┐
│  SQLite │ PostgreSQL │ MySQL │ Custom Implementation    │
└─────────────────────────────────────────────────────────────┘
```

## 🔌 Core Interface

### [`IDatabaseAdapter`](src/database/adapter.ts)

The core interface that all adapters must implement:

```typescript
interface IDatabaseAdapter {
  // Connection Management
  getConnection(): DatabaseConnection;
  initialize(): Promise<void>;
  close(): Promise<void>;
  isConnected(): boolean;
  
  // Configuration
  getConfig(): DatabaseAdapterConfig;
  getDatabaseType(): DatabaseType;
  getSqlHelpers(): SqlHelpers;
  
  // Optional: Custom methods
  [key: string]: any;
}
```

### DatabaseConnection

Interface for database connections:

```typescript
interface DatabaseConnection {
  // Query execution
  query(sql: string, params?: any[]): QueryResult;
  execute(sql: string, params?: any[]): ExecuteResult;
  
  // Transaction support
  beginTransaction(): Promise<void>;
  commitTransaction(): Promise<void>;
  rollbackTransaction(): Promise<void>;
  
  // Connection lifecycle
  close(): void;
  isClosed(): boolean;
}
```

### DatabaseAdapterConfig

Configuration interface for adapters:

```typescript
interface DatabaseAdapterConfig {
  // Connection settings
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  password?: string;
  
  // Connection pool settings
  maxConnections?: number;
  minConnections?: number;
  idleTimeout?: number;
  
  // Custom settings
  ssl?: boolean;
  timezone?: string;
  [key: string]: any;
}
```

### SqlHelpers

SQL generation helpers for different databases:

```typescript
interface SqlHelpers {
  // Data type mapping
  mapDataType(type: string): string;
  
  // Value formatting
  formatDefaultValue(value: any): string;
  formatValue(value: any): string;
  
  // Query generation
  getRandomOrder(): string;
  getPrimaryKeyQuery(tableName: string): string;
  getTableInfoQuery(tableName: string): string;
  
  // Limit/offset
  getLimitClause(limit: number, offset?: number): string;
  
  // Index handling
  getCreateIndexSQL(indexName: string, tableName: string, columns: string[]): string;
}
```

## 🔧 Built-in Adapters

### BunSQLiteAdapter

Default adapter for Bun's SQLite implementation.

```typescript
import { BunSQLiteAdapter } from 'open-bauth/src/database/adapter';

const adapter = new BunSQLiteAdapter({
  database: new Database('auth.db'),
  options: {
    readonly: false,
    create: true
  }
});
```

**Features**:
- Full SQLite feature support
- In-memory and file-based databases
- Transaction support
- WAL mode for concurrency
- Backup and restore functionality

### JsonFileAdapter

File-based adapter using JSON for storage.

```typescript
import { JsonFileAdapter } from './examples/custom-adapter-example';

const adapter = new JsonFileAdapter({
  filePath: './data/auth.json',
  autoSave: true,
  backup: true,
  encryptionKey: 'optional-encryption-key'
});
```

**Features**:
- Human-readable JSON storage
- Automatic backup creation
- Optional encryption
- Atomic writes
- Full-text search support

### MemoryAdapter

In-memory adapter for testing and temporary storage.

```typescript
import { MemoryAdapter } from './examples/custom-adapter-example';

const adapter = new MemoryAdapter({
  maxSize: 1000, // Maximum records
  ttl: 3600000, // 1 hour TTL
  persistence: false // No persistence
});
```

**Features**:
- Zero-latency operations
- TTL support for records
- Memory usage limits
- Perfect for testing
- Event-driven persistence

## 🛠️ Creating Custom Adapters

### Step 1: Implement the Interface

Create a class that implements `IDatabaseAdapter`:

```typescript
import { IDatabaseAdapter, DatabaseConnection, DatabaseAdapterConfig } from 'open-bauth/src/database/adapter';

export class PostgreSQLAdapter implements IDatabaseAdapter {
  private connection: DatabaseConnection;
  private config: DatabaseAdapterConfig;
  
  constructor(config: DatabaseAdapterConfig) {
    this.config = config;
  }
  
  async initialize(): Promise<void> {
    // Initialize PostgreSQL connection
    this.connection = new PostgreSQLConnection(this.config);
    await this.connection.connect();
  }
  
  getConnection(): DatabaseConnection {
    return this.connection;
  }
  
  async close(): Promise<void> {
    await this.connection.close();
  }
  
  isConnected(): boolean {
    return this.connection && !this.connection.isClosed();
  }
  
  getConfig(): DatabaseAdapterConfig {
    return this.config;
  }
  
  getDatabaseType(): DatabaseType {
    return {
      isSQLite: false,
      isPostgreSQL: true,
      isMySQL: false,
      isCustom: false
    };
  }
  
  getSqlHelpers(): SqlHelpers {
    return {
      mapDataType: (type: string) => this.mapPostgreSQLType(type),
      formatDefaultValue: (value: any) => this.formatPostgreSQLValue(value),
      getRandomOrder: () => 'ORDER BY RANDOM()',
      getPrimaryKeyQuery: (tableName: string) => `SELECT * FROM ${tableName} LIMIT 1`,
      getTableInfoQuery: (tableName: string) => `SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '${tableName}'`,
      getLimitClause: (limit: number, offset?: number) => {
        const sql = `LIMIT ${limit}`;
        return offset ? `${sql} OFFSET ${offset}` : sql;
      },
      getCreateIndexSQL: (indexName: string, tableName: string, columns: string[]) => {
        return `CREATE INDEX ${indexName} ON ${tableName} (${columns.join(', ')})`;
      }
    };
  }
  
  // Custom methods
  async getTableSize(tableName: string): Promise<number> {
    const result = await this.connection.query(`SELECT COUNT(*) as count FROM ${tableName}`);
    return result.rows[0].count;
  }
  
  private mapPostgreSQLType(type: string): string {
    const typeMap: Record<string, string> = {
      'TEXT': 'TEXT',
      'INTEGER': 'INTEGER',
      'BOOLEAN': 'BOOLEAN',
      'DATETIME': 'TIMESTAMP',
      'BIT': 'BIT'
    };
    return typeMap[type] || 'TEXT';
  }
  
  private formatPostgreSQLValue(value: any): string {
    if (value === null) return 'NULL';
    if (typeof value === 'string') return `'${value.replace(/'/g, "''")}'`;
    if (typeof value === 'boolean') return value ? 'TRUE' : 'FALSE';
    return String(value);
  }
}
```

### Step 2: Create Database Connection

Implement the `DatabaseConnection` interface:

```typescript
class PostgreSQLConnection implements DatabaseConnection {
  private client: any; // PostgreSQL client
  private config: DatabaseAdapterConfig;
  
  constructor(config: DatabaseAdapterConfig) {
    this.config = config;
  }
  
  async connect(): Promise<void> {
    const { Client } = require('pg');
    this.client = new Client({
      host: this.config.host,
      port: this.config.port,
      database: this.config.database,
      user: this.config.username,
      password: this.config.password
    });
    await this.client.connect();
  }
  
  async query(sql: string, params: any[] = []): Promise<QueryResult> {
    try {
      const result = await this.client.query(sql, params);
      return {
        success: true,
        rows: result.rows,
        rowCount: result.rowCount,
        lastInsertRowid: null
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        rows: [],
        rowCount: 0
      };
    }
  }
  
  async execute(sql: string, params: any[] = []): Promise<ExecuteResult> {
    const result = await this.query(sql, params);
    return {
      success: result.success,
      changes: result.rowCount,
      lastInsertRowid: null
    };
  }
  
  async beginTransaction(): Promise<void> {
    await this.client.query('BEGIN');
  }
  
  async commitTransaction(): Promise<void> {
    await this.client.query('COMMIT');
  }
  
  async rollbackTransaction(): Promise<void> {
    await this.client.query('ROLLBACK');
  }
  
  close(): void {
    if (this.client) {
      this.client.end();
    }
  }
  
  isClosed(): boolean {
    return !this.client || this.client._ending;
  }
}
```

### Step 3: Register the Adapter

Register your custom adapter for easy access:

```typescript
import { AdapterFactory } from 'open-bauth/src/database/adapter';

// Register adapter
AdapterFactory.register('postgresql', PostgreSQLAdapter);

// Use registered adapter
const adapter = AdapterFactory.create('postgresql', {
  host: 'localhost',
  port: 5432,
  database: 'auth_db',
  username: 'user',
  password: 'password'
});
```

## 🏭 Adapter Factory

### Creating Adapters

Use the factory to create adapter instances:

```typescript
import { AdapterFactory } from 'open-bauth/src/database/adapter';

// Create with type
const sqliteAdapter = AdapterFactory.create('sqlite', {
  database: new Database('auth.db')
});

// Create with class
const customAdapter = AdapterFactory.createWithClass(CustomAdapter, {
  connectionString: 'custom://localhost'
});
```

### Available Factory Methods

- `create(type, config)`: Create adapter by type
- `createWithClass(AdapterClass, config)`: Create with specific class
- `register(type, AdapterClass)`: Register custom adapter type
- `getAvailableTypes()`: Get list of available adapter types
- `getAdapterInfo(type)`: Get metadata about adapter type

## 💡 Usage Examples

### Using Custom Adapter with BaseController

```typescript
import { BaseController } from 'open-bauth/src/database/base-controller';
import { CustomAdapter } from './adapters/custom-adapter';

// Create custom adapter
const customAdapter = new CustomAdapter({
  connectionString: "custom://localhost",
  timeout: 30000,
  maxConnections: 10
});

// Use with BaseController
const userController = new BaseController("users", {
  adapter: customAdapter
});

// All existing methods work the same
const users = await userController.findAll();
const user = await userController.findById(1);
const newUser = await userController.create({
  name: "John Doe",
  email: "john@example.com"
});
```

### Multiple Adapters in Same Application

```typescript
// Different adapters for different purposes
const mainAdapter = new PostgreSQLAdapter(mainConfig);
const cacheAdapter = new MemoryAdapter({ maxSize: 1000 });
const analyticsAdapter = new ClickHouseAdapter(analyticsConfig);

// Use different controllers
const userController = new BaseController("users", { adapter: mainAdapter });
const sessionController = new BaseController("sessions", { adapter: cacheAdapter });
const metricsController = new BaseController("metrics", { adapter: analyticsAdapter });
```

### Adapter Switching

```typescript
// Runtime adapter switching
class AdapterManager {
  private currentAdapter: IDatabaseAdapter;
  
  async switchToPostgreSQL(config: DatabaseAdapterConfig): Promise<void> {
    const newAdapter = new PostgreSQLAdapter(config);
    await newAdapter.initialize();
    
    // Close current adapter
    if (this.currentAdapter) {
      await this.currentAdapter.close();
    }
    
    // Switch to new adapter
    this.currentAdapter = newAdapter;
  }
  
  getController(tableName: string): BaseController {
    return new BaseController(tableName, {
      adapter: this.currentAdapter
    });
  }
}
```

## 🎯 Best Practices

### Performance Optimization

1. **Connection Pooling**: Implement connection pooling for production
2. **Batch Operations**: Use batch inserts/updates when possible
3. **Index Optimization**: Create appropriate indexes for queries
4. **Query Caching**: Cache frequent query results
5. **Prepared Statements**: Use prepared statements for repeated queries

### Error Handling

1. **Consistent Errors**: Use standard error format across adapters
2. **Connection Recovery**: Implement automatic reconnection logic
3. **Transaction Safety**: Ensure proper transaction cleanup
4. **Resource Cleanup**: Properly close connections and statements
5. **Timeout Handling**: Implement appropriate timeouts for operations

### Security Considerations

1. **Parameterized Queries**: Always use parameterized queries
2. **Connection Security**: Use SSL/TLS for database connections
3. **Credential Management**: Securely store database credentials
4. **Access Control**: Implement proper database user permissions
5. **Audit Logging**: Log all database operations for security

### Testing

1. **Mock Adapters**: Create mock adapters for unit testing
2. **In-Memory Testing**: Use memory adapters for fast tests
3. **Transaction Testing**: Test transaction rollback scenarios
4. **Load Testing**: Test with realistic data volumes
5. **Integration Testing**: Test with real database instances

## 🔍 Advanced Features

### Custom SQL Generation

```typescript
class AdvancedAdapter implements IDatabaseAdapter {
  getSqlHelpers(): SqlHelpers {
    return {
      // Custom limit clause with optimization hints
      getLimitClause: (limit: number, offset?: number) => {
        if (offset) {
          return `LIMIT ${limit} OFFSET ${offset} /* OPTIMIZED */`;
        }
        return `LIMIT ${limit}`;
      },
      
      // Custom value formatting for special types
      formatValue: (value: any) => {
        if (value instanceof Date) {
          return `'${value.toISOString()}'`;
        }
        if (Array.isArray(value)) {
          return `ARRAY[${value.map(v => this.formatValue(v)).join(', ')}]`;
        }
        return this.defaultFormatValue(value);
      }
    };
  }
}
```

### Health Monitoring

```typescript
interface HealthCheckAdapter extends IDatabaseAdapter {
  // Health check methods
  healthCheck(): Promise<HealthStatus>;
  getConnectionMetrics(): ConnectionMetrics;
  getPerformanceMetrics(): PerformanceMetrics;
}

class MonitoredAdapter implements HealthCheckAdapter {
  async healthCheck(): Promise<HealthStatus> {
    try {
      const start = Date.now();
      await this.connection.query('SELECT 1');
      const responseTime = Date.now() - start;
      
      return {
        status: 'healthy',
        responseTime,
        timestamp: new Date().toISOString(),
        details: {
          connected: this.isConnected(),
          activeConnections: this.getActiveConnections()
        }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
}
```

### Migration Support

```typescript
interface MigrationAdapter extends IDatabaseAdapter {
  // Migration methods
  createMigrationTable(): Promise<void>;
  getAppliedMigrations(): Promise<Migration[]>;
  applyMigration(migration: Migration): Promise<void>;
  rollbackMigration(migration: Migration): Promise<void>;
}

class MigrationAwareAdapter implements MigrationAdapter {
  async createMigrationTable(): Promise<void> {
    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        rollback_sql TEXT
      )
    `;
    await this.connection.execute(createTableSQL);
  }
  
  async applyMigration(migration: Migration): Promise<void> {
    await this.beginTransaction();
    try {
      await this.connection.execute(migration.upSQL);
      await this.connection.execute(
        'INSERT INTO migrations (name, up_sql, down_sql) VALUES (?, ?, ?)',
        [migration.name, migration.upSQL, migration.downSQL]
      );
      await this.commitTransaction();
    } catch (error) {
      await this.rollbackTransaction();
      throw error;
    }
  }
}
```

---

See [`examples/custom-adapter-example.ts`](../examples/custom-adapter-example.ts) for complete JsonFileAdapter and MemoryAdapter implementations with real methods (getCurrentCounter, incrementCounter).
