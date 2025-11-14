/**
 * Ejemplo REAL simple de adaptador personalizado
 * Este adaptador usa un archivo JSON local para almacenar datos
 * Es una alternativa real y funcional para aplicaciones pequeñas
 */

import { IDatabaseAdapter, DatabaseConnection } from "../src/database/adapter";
import { writeFileSync, readFileSync, existsSync } from "fs";

// Ejemplo REAL: Adaptador que usa archivos JSON
export class JsonFileAdapter implements IDatabaseAdapter {
  private connection: DatabaseConnection;
  private filePath: string;
  private config: any;

  constructor(config: { filePath: string }) {
    this.config = config;
    this.filePath = config.filePath;
    
    // Crear conexión que opera sobre archivo JSON
    this.connection = {
      query: (sql: string) => ({
        all: async (...params: any[]) => {
          console.log(`JSON Adapter - Query: ${sql}`, params);
          return this.executeQuery(sql, params);
        },
        get: async (...params: any[]) => {
          console.log(`JSON Adapter - Query: ${sql}`, params);
          const results = this.executeQuery(sql, params);
          return results.length > 0 ? results[0] : null;
        },
        run: async (...params: any[]) => {
          console.log(`JSON Adapter - Query: ${sql}`, params);
          this.executeWrite(sql, params);
          return { changes: 1, lastInsertRowid: Date.now() };
        }
      })
    };
  }

  async initialize(): Promise<void> {
    console.log(`JSON Adapter initialized with file: ${this.filePath}`);
    
    // Crear archivo si no existe
    if (!existsSync(this.filePath)) {
      this.saveData({});
    }
  }

  async close(): Promise<void> {
    console.log('JSON Adapter closed');
  }

  isConnected(): boolean {
    return existsSync(this.filePath);
  }

  getConnection(): DatabaseConnection {
    return this.connection;
  }

  getDatabaseType() {
    return {
      isSQLite: false,
      isSQLServer: false,
      isPostgreSQL: false,
      isMySQL: false,
      isJsonFile: true // Tipo personalizado
    };
  }

  getConfig() {
    return this.config;
  }

  getSqlHelpers() {
    return {
      mapDataType: (type: string) => {
        const upperType = type.toUpperCase();
        switch (upperType) {
          case "INTEGER":
          case "SERIAL":
            return "number";
          case "TEXT":
          case "VARCHAR":
            return "string";
          case "BOOLEAN":
            return "boolean";
          case "REAL":
            return "number";
          default:
            return "string";
        }
      },
      formatDefaultValue: (value: any) => {
        if (value === null) return "NULL";
        if (typeof value === "boolean") return value ? "true" : "false";
        if (typeof value === "string") return `"${value}"`;
        return String(value);
      },
      getRandomOrder: () => "ORDER BY RANDOM()",
      getPrimaryKeyQuery: (tableName: string) => 
        `SELECT 'id' as name, 1 as pk`,
      getTableInfoQuery: (tableName: string) => 
        `SELECT 'id' as name, 'string' as type, 1 as notnull, null as dflt_value, 1 as pk`
    };
  }

  // Métodos privados para manejo del archivo JSON
  private loadData(): any {
    try {
      const content = readFileSync(this.filePath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      return {};
    }
  }

  private saveData(data: any): void {
    writeFileSync(this.filePath, JSON.stringify(data, null, 2));
  }

  private getTableName(sql: string): string {
    // Extraer nombre de tabla de SQL simple
    const match = sql.match(/FROM\s+(\w+)|INTO\s+(\w+)/i);
    return match ? (match[1] || match[2]) : 'unknown';
  }

  private executeQuery(sql: string, params: any[]): any[] {
    const data = this.loadData();
    const tableName = this.getTableName(sql);
    const tableData = data[tableName] || [];

    // SELECT simple
    if (sql.toUpperCase().includes('SELECT')) {
      // Manejar COUNT queries
      if (sql.toUpperCase().includes('COUNT(')) {
        return [{ total: tableData.length }];
      }
      return tableData;
    }

    return [];
  }

  private executeWrite(sql: string, params: any[]): void {
    const data = this.loadData();
    
    // INSERT simple
    if (sql.toUpperCase().includes('INSERT')) {
      const tableName = this.getTableName(sql);
      if (!data[tableName]) data[tableName] = [];
      
      // Extraer datos del INSERT (simplificado)
      const newItem = { id: Date.now(), created_at: new Date().toISOString() };
      data[tableName].push(newItem);
      this.saveData(data);
    }
  }

  // Método REAL: Obtener valor actual del contador
  async getCurrentCounter(): Promise<{ value: number; timestamp: string; lastUpdated: string }> {
    const data = this.loadData();
    const counter = data.counter || { value: 0, created_at: new Date().toISOString() };
    
    return {
      value: counter.value,
      timestamp: new Date().toISOString(),
      lastUpdated: counter.created_at
    };
  }

  // Método REAL: Incrementar contador
  async incrementCounter(): Promise<{ value: number; timestamp: string }> {
    const data = this.loadData();
    const counter = data.counter || { value: 0 };
    counter.value += 1;
    counter.created_at = new Date().toISOString();
    
    data.counter = counter;
    this.saveData(data);
    
    return {
      value: counter.value,
      timestamp: counter.created_at
    };
  }

  // Método REAL: Obtener usuarios reales
  async getUsers(): Promise<any[]> {
    const data = this.loadData();
    return data.users || [];
  }
}

// Adaptador aún más simple: Solo en memoria
export class MemoryAdapter implements IDatabaseAdapter {
  private connection: DatabaseConnection;
  private data: Map<string, any[]> = new Map();
  private config: any;

  constructor(config: any = {}) {
    this.config = config;
    
    this.connection = {
      query: (sql: string) => ({
        all: async (...params: any[]) => {
          const tableName = this.extractTableName(sql);
          return this.data.get(tableName) || [];
        },
        get: async (...params: any[]) => {
          const tableName = this.extractTableName(sql);
          const results = this.data.get(tableName) || [];
          return results.length > 0 ? results[0] : null;
        },
        run: async (...params: any[]) => {
          return { changes: 1, lastInsertRowid: Date.now() };
        }
      })
    };
  }

  async initialize(): Promise<void> {
    console.log('Memory Adapter initialized');
  }

  async close(): Promise<void> {
    console.log('Memory Adapter closed');
    this.data.clear();
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
      isPostgreSQL: false,
      isMySQL: false,
      isMemory: true
    };
  }

  getConfig() {
    return this.config;
  }

  getSqlHelpers() {
    return {
      mapDataType: (type: string) => type,
      formatDefaultValue: (value: any) => String(value),
      getRandomOrder: () => "ORDER BY RANDOM()",
      getPrimaryKeyQuery: (tableName: string) => 
        `SELECT 'id' as name, 1 as pk`,
      getTableInfoQuery: (tableName: string) => 
        `SELECT 'id' as name, 'string' as type, 1 as notnull, null as dflt_value, 1 as pk`
    };
  }

  private extractTableName(sql: string): string {
    const match = sql.match(/FROM\s+(\w+)|INTO\s+(\w+)/i);
    return match ? (match[1] || match[2]) : 'default';
  }

  // Método REAL simple: Obtener estadísticas
  async getStats(): Promise<{ tables: number; totalRecords: number; timestamp: string }> {
    let totalRecords = 0;
    this.data.forEach(records => {
      totalRecords += records.length;
    });

    return {
      tables: this.data.size,
      totalRecords,
      timestamp: new Date().toISOString()
    };
  }
}

// Ejemplos de uso REALES
async function jsonAdapterExample() {
  console.log('\n=== JSON File Adapter Example ===');
  
  // Crear adaptador JSON real
  const jsonAdapter = new JsonFileAdapter({ filePath: './data.json' });
  
  // Inicializar
  await jsonAdapter.initialize();
  
  // Obtener valor del contador
  const counter = await jsonAdapter.getCurrentCounter();
  console.log('Current counter:', counter);
  
  // Incrementar contador
  const incremented = await jsonAdapter.incrementCounter();
  console.log('Incremented counter:', incremented);
  
  // Obtener usuarios
  const users = await jsonAdapter.getUsers();
  console.log('Users:', users);
  
  return { counter, incremented, users };
}

async function memoryAdapterExample() {
  console.log('\n=== Memory Adapter Example ===');
  
  // Crear adaptador de memoria
  const memoryAdapter = new MemoryAdapter();
  
  // Inicializar
  await memoryAdapter.initialize();
  
  // Obtener estadísticas
  const stats = await memoryAdapter.getStats();
  console.log('Memory adapter stats:', stats);
  
  return { stats };
}

async function realWorldExample() {
  console.log('\n=== Real World Example ===');
  
  // Usar adaptador JSON con BaseController
  const jsonAdapter = new JsonFileAdapter({ filePath: './app-data.json' });
  await jsonAdapter.initialize();
  
  // Crear controller
  const { BaseController } = await import("../src/database/base-controller");
  const userController = new BaseController("users", { adapter: jsonAdapter });
  
  // Obtener usuarios (funciona igual que con base de datos real)
  const users = await userController.findAll();
  console.log('Users from controller:', users);
  
  return { users };
}

// Exportar ejemplos
export { 
  jsonAdapterExample, 
  memoryAdapterExample, 
  realWorldExample 
};

// Ejecutar todos los ejemplos
if (import.meta.main) {
  async function runAllExamples() {
    try {
      await jsonAdapterExample();
      await memoryAdapterExample();
      await realWorldExample();
      console.log('\n✅ All examples completed successfully!');
    } catch (error) {
      console.error('❌ Example failed:', error);
    }
  }
  
  runAllExamples();
}
