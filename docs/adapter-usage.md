# Sistema de Adaptadores de Base de Datos

Esta documentación explica cómo utilizar el sistema de adaptadores de base de datos de la librería, que permite una flexibilidad completa para trabajar con diferentes tipos de bases de datos.

## Overview

El sistema de adaptadores permite:
- Usar la base de datos de Bun SQL por defecto
- Integrar adaptadores personalizados para otras bases de datos
- Mantener compatibilidad con el código existente
- Extender funcionalidades según necesidades específicas

## Uso Básico

### 1. Usar Adaptador por Defecto (Bun SQL)

```typescript
import { BaseController } from "./src/database/base-controller";
import { SQL } from "bun";

// Usar base de datos directamente (mantiene compatibilidad)
const db = SQL("my-database.sqlite");
const userController = new BaseController("users", {
  database: db,
  isSQLite: true
});

// O especificar el tipo de base de datos
const postgresController = new BaseController("users", {
  database: db,
  isSQLServer: false,
  isSQLite: false
});
```

### 2. Usar Adaptador Personalizado

```typescript
import { BaseController } from "./src/database/base-controller";
import { SimpleCustomAdapter } from "./examples/custom-adapter-example";

// Crear adaptador personalizado
const customAdapter = new SimpleCustomAdapter({
  connectionString: "custom://localhost"
});

// Usar con BaseController
const customController = new BaseController("users", {
  adapter: customAdapter
});
```

## Crear un Adaptador Personalizado

### Interfaz Básica

Todo adaptador debe implementar la interfaz `IDatabaseAdapter`:

```typescript
interface IDatabaseAdapter {
  // Conexión
  getConnection(): DatabaseConnection;
  initialize(): Promise<void>;
  close(): Promise<void>;
  isConnected(): boolean;
  
  // Configuración
  getConfig(): any;
  getDatabaseType(): DatabaseType;
  getSqlHelpers(): SqlHelpers;
}
```

### Ejemplo Completo

```typescript
import { IDatabaseAdapter, DatabaseConnection } from "./src/database/adapter";

export class MiAdaptadorPersonalizado implements IDatabaseAdapter {
  private connection: DatabaseConnection;
  private config: any;

  constructor(config: any) {
    this.config = config;
    this.connection = this.createConnection();
  }

  async initialize(): Promise<void> {
    // Inicializar conexión
    console.log('Adapter initialized');
  }

  async close(): Promise<void> {
    // Cerrar conexión
    console.log('Adapter closed');
  }

  isConnected(): boolean {
    // Verificar estado de conexión
    return true;
  }

  getConnection(): DatabaseConnection {
    return this.connection;
  }

  getDatabaseType() {
    return {
      isSQLite: false,
      isSQLServer: false,
      isPostgreSQL: false,
      isMySQL: false
    };
  }

  getConfig() {
    return this.config;
  }

  getSqlHelpers() {
    return {
      mapDataType: (type: string) => {
        // Mapear tipos de datos
        switch (type.toUpperCase()) {
          case "INTEGER": return "INTEGER";
          case "TEXT": return "TEXT";
          case "BOOLEAN": return "INTEGER";
          default: return "TEXT";
        }
      },
      formatDefaultValue: (value: any) => {
        // Formatear valores por defecto
        if (value === null) return "NULL";
        if (typeof value === "boolean") return value ? "1" : "0";
        return `'${String(value)}'`;
      },
      getRandomOrder: () => "ORDER BY RANDOM()",
      getPrimaryKeyQuery: (tableName: string) => 
        `SELECT column_name as name, 1 as pk FROM information_schema.columns WHERE table_name = '${tableName}' AND column_name = 'id'`,
      getTableInfoQuery: (tableName: string) => 
        `SELECT column_name as name, data_type as type FROM information_schema.columns WHERE table_name = '${tableName}'`
    };
  }

  private createConnection(): DatabaseConnection {
    // Crear conexión personalizada
    return {
      query: (sql: string) => ({
        all: async (...params: any[]) => {
          // Ejecutar consulta que retorna múltiples resultados
          return [];
        },
        get: async (...params: any[]) => {
          // Ejecutar consulta que retorna un solo resultado
          return null;
        },
        run: async (...params: any[]) => {
          // Ejecutar consulta que no retorna resultados
          return { changes: 1, lastInsertRowid: 1 };
        }
      })
    };
  }
}
```

## Métodos Personalizados

Los adaptadores pueden incluir métodos personalizados:

```typescript
export class AdvancedCustomAdapter implements IDatabaseAdapter {
  // ... métodos requeridos ...

  // Métodos personalizados
  async getHealthStatus(): Promise<{ status: string; latency: number }> {
    const start = Date.now();
    await this.connection.query("SELECT 1").get();
    const latency = Date.now() - start;
    
    return {
      status: "healthy",
      latency
    };
  }

  async backupTable(tableName: string): Promise<string> {
    // Implementar backup personalizado
    return `backup_${tableName}_${Date.now()}.sql`;
  }

  // Método simple para obtener un valor como solicitaste
  async getSimpleValue(): Promise<{ value: number; timestamp: string }> {
    return {
      value: 42,
      timestamp: new Date().toISOString()
    };
  }
}
```

## Configuración de BaseController

### Opciones Disponibles

```typescript
interface BaseControllerOptions {
  // Base de datos directa (compatibilidad)
  database?: SQL | Database;
  
  // Adaptador personalizado
  adapter?: IDatabaseAdapter;
  
  // Esquemas de validación
  schemas?: SchemaCollection;
  
  // Tipos de base de datos (para adaptador por defecto)
  isSQLite?: boolean;
  isSQLServer?: boolean;
}
```

### Ejemplos de Configuración

```typescript
// 1. Base de datos SQLite directa
const sqliteController = new BaseController("users", {
  database: mySqliteDatabase,
  isSQLite: true
});

// 2. Base de datos PostgreSQL directa
const postgresController = new BaseController("users", {
  database: myPostgresDatabase,
  isSQLite: false,
  isSQLServer: false
});

// 3. Adaptador personalizado
const customController = new BaseController("users", {
  adapter: myCustomAdapter
});

// 4. Con validación de esquemas
const validatedController = new BaseController("users", {
  database: myDatabase,
  schemas: {
    users: {
      create: userCreateSchema,
      update: userUpdateSchema
    }
  }
});
```

## Buenas Prácticas

### 1. Manejo de Errores

```typescript
export class RobustCustomAdapter implements IDatabaseAdapter {
  async initialize(): Promise<void> {
    try {
      await this.connect();
    } catch (error) {
      console.error('Failed to initialize adapter:', error);
      throw error;
    }
  }

  private async connect(): Promise<void> {
    // Lógica de conexión con reintentos
    let retries = 3;
    while (retries > 0) {
      try {
        // Intentar conexión
        break;
      } catch (error) {
        retries--;
        if (retries === 0) throw error;
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }
}
```

### 2. Pool de Conexiones

```typescript
export class PooledCustomAdapter implements IDatabaseAdapter {
  private pool: any[] = [];
  private maxConnections = 10;

  getConnection(): DatabaseConnection {
    // Obtener conexión del pool
    const connection = this.pool.pop() || this.createConnection();
    return connection;
  }

  releaseConnection(connection: DatabaseConnection): void {
    if (this.pool.length < this.maxConnections) {
      this.pool.push(connection);
    }
  }
}
```

### 3. Logging y Métricas

```typescript
export class MonitoredCustomAdapter implements IDatabaseAdapter {
  private queryCount = 0;
  private totalTime = 0;

  getConnection(): DatabaseConnection {
    return {
      query: (sql: string) => {
        const start = Date.now();
        
        return {
          all: async (...params: any[]) => {
            this.queryCount++;
            const result = await this.execute(sql, params);
            this.totalTime += Date.now() - start;
            return result;
          },
          // ... otros métodos
        };
      }
    };
  }

  getMetrics() {
    return {
      queryCount: this.queryCount,
      averageTime: this.totalTime / this.queryCount,
      totalTime: this.totalTime
    };
  }
}
```

## Ejemplo Completo de Uso

```typescript
import { BaseController } from "./src/database/base-controller";
import { SimpleCustomAdapter } from "./examples/custom-adapter-example";

async function completeExample() {
  // Crear adaptador personalizado
  const customAdapter = new SimpleCustomAdapter({
    name: "MyCustomDB",
    version: "1.0.0"
  });

  // Inicializar adaptador
  await customAdapter.initialize();

  // Crear controller con adaptador personalizado
  const userController = new BaseController("users", {
    adapter: customAdapter
  });

  // Usar métodos del controller
  const users = await userController.findAll();
  console.log('Users found:', users);

  // Usar métodos personalizados del adaptador
  if (customAdapter.getSimpleValue) {
    const simpleValue = await customAdapter.getSimpleValue();
    console.log('Simple value:', simpleValue);
  }

  // Cerrar adaptador
  await customAdapter.close();
}

// Ejecutar ejemplo
completeExample().catch(console.error);
```

## Conclusión

El sistema de adaptadores proporciona:

✅ **Flexibilidad**: Soporta múltiples tipos de bases de datos
✅ **Compatibilidad**: Mantienes código existente sin cambios
✅ **Extensibilidad**: Agrega funcionalidades personalizadas
✅ **Simplicidad**: Fácil de implementar y usar
✅ **Mantenibilidad**: Código limpio y modular

Esto permite que la librería sea adaptable a diferentes necesidades mientras mantiene una API consistente.
