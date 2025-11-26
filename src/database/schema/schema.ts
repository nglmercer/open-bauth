import type { ColumnDefinition, ColumnType, TableSchema } from "../base-controller";

// ==========================================
// 1. Definición de Tipos y Interfaces
// ==========================================

type ConstructorType = 
  | StringConstructor 
  | NumberConstructor 
  | BooleanConstructor 
  | DateConstructor 
  | ObjectConstructor 
  | ArrayConstructor;

export interface SchemaIndex {
  name: string;
  columns: string[];
  unique?: boolean;
}

export interface SchemaOptions {
  indexes?: SchemaIndex[];
}

export interface SchemaTypeOptions {
  type: ConstructorType | ColumnType;
  required?: boolean;           // Mapea a notNull
  unique?: boolean;
  primaryKey?: boolean;         // <--- Agregado para soportar tus IDs
  default?: any;
  ref?: string;
  references?: {
    table: string;
    column: string;
  };
  check?: string;
  notNull?: boolean;            // Alias directo
}

type SchemaField = 
  | ConstructorType 
  | SchemaTypeOptions 
  | { [key: string]: SchemaField } 
  | SchemaField[];

export interface SchemaDefinition {
  [key: string]: SchemaField;
}

// ==========================================
// 2. Clase Schema Principal
// ==========================================

export class Schema {
  private definition: SchemaDefinition;
  private options: SchemaOptions;

  constructor(definition: SchemaDefinition, options: SchemaOptions = {}) {
    this.definition = definition;
    this.options = options;
  }

  public toTableSchema(tableName: string): TableSchema {
    const columns = this.parseColumns();
    const indexes = this.options.indexes || [];

    return {
      tableName,
      columns,
      indexes: indexes.length > 0 ? indexes : undefined
    };
  }

  public getColumns(): ColumnDefinition[] {
    return this.parseColumns();
  }

  private parseColumns(): ColumnDefinition[] {
    const columns: ColumnDefinition[] = [];
    for (const [name, value] of Object.entries(this.definition)) {
      columns.push(this.parseField(name, value));
    }
    return columns;
  }

  private parseField(name: string, value: any): ColumnDefinition {
    // 1. Shorthand: name: String
    if (this.isConstructor(value)) {
      return {
        name,
        type: this.mapConstructorToSQL(value),
      };
    }

    // 2. Array
    if (Array.isArray(value)) {
      return { name, type: "TEXT", defaultValue: "[]" };
    }

    // 3. Objeto anidado sin 'type'
    if (typeof value === "object" && !value.type && !this.isConstructor(value)) {
       return { name, type: "TEXT", defaultValue: "{}" };
    }

    // 4. Configuración completa
    if (typeof value === "object" && value.type) {
      const sqlColumn: ColumnDefinition = {
        name,
        type: this.mapConstructorToSQL(value.type),
      };

      if (value.required || value.notNull) sqlColumn.notNull = true;
      if (value.unique) sqlColumn.unique = true;
      if (value.primaryKey) sqlColumn.primaryKey = true;
      if (value.check) sqlColumn.check = value.check;

      if (value.references) {
        sqlColumn.references = value.references;
      } else if (value.ref) {
        sqlColumn.references = { table: value.ref, column: "id" };
      }
      
      if (value.default !== undefined) {
        if (value.default === Date.now) {
          sqlColumn.defaultValue = "CURRENT_TIMESTAMP";
        } else if (typeof value.default === 'function') {
           // Nota: Si pasas una función generadora de IDs en JS, 
           // aquí se ejecutará solo al crear el esquema, no en cada insert.
           // Para SQL puro es mejor pasar el string SQL.
           sqlColumn.defaultValue = value.default(); 
        } else {
          sqlColumn.defaultValue = value.default;
        }
      }

      return sqlColumn;
    }

    return { name, type: "TEXT" };
  }

  private isConstructor(value: any): boolean {
    return [String, Number, Boolean, Date, Object, Array].includes(value);
  }

  private mapConstructorToSQL(type: any): ColumnType {
    if (type === String) return "TEXT";
    if (type === Number) return "INTEGER"; 
    if (type === Boolean) return "BOOLEAN";
    if (type === Date) return "DATETIME";
    if (type === Object || type === Array) return "TEXT";
    if (typeof type === "string") return type as ColumnType;
    return "TEXT";
  }
}