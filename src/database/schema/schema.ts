import type { ColumnDefinition, ColumnType, TableSchema } from "../base-controller.ts";

type ConstructorType = 
  | StringConstructor 
  | NumberConstructor 
  | BooleanConstructor 
  | DateConstructor 
  | ObjectConstructor 
  | ArrayConstructor
  | BufferConstructor;

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
  required?: boolean;
  notNull?: boolean;
  unique?: boolean;
  primaryKey?: boolean;
  default?: any;
  ref?: string;
  references?: {
    table: string;
    column: string;
  };
  check?: string;
}

type SchemaField = 
  | ConstructorType 
  | SchemaTypeOptions 
  | { [key: string]: SchemaField } 
  | SchemaField[];

export interface SchemaDefinition {
  [key: string]: SchemaField;
}

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

  public getDefinition(): SchemaDefinition {
    return this.definition;
  }

  private parseColumns(): ColumnDefinition[] {
    return Object.entries(this.definition).map(([name, value]) => 
      this.parseField(name, value)
    );
  }

  private parseField(name: string, value: any): ColumnDefinition {
    if (this.isConstructor(value)) {
      return {
        name,
        type: this.mapConstructorToSQL(value),
      };
    }

    if (Array.isArray(value)) {
      return { name, type: "TEXT", defaultValue: "[]" };
    }

    if (typeof value === "object" && !value.type && !this.isConstructor(value)) {
       return { name, type: "TEXT", defaultValue: "{}" };
    }

    if (typeof value === "object" && value.type) {
      const sqlColumn: ColumnDefinition = {
        name,
        type: this.mapConstructorToSQL(value.type),
      };

      if (value.primaryKey) {
        sqlColumn.primaryKey = true;
        sqlColumn.notNull = true; // Las columnas primaryKey siempre deben ser notNull
      } else if (value.required ?? value.notNull) {
        sqlColumn.notNull = true;
      }
      if (value.unique) sqlColumn.unique = true;
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
    return [String, Number, Boolean, Date, Object, Array, Buffer].includes(value);
  }

  private mapConstructorToSQL(type: any): ColumnType {
    if (typeof type === "string") return type as ColumnType;

    switch (type) {
      case String: return "TEXT";
      case Number: return "INTEGER";
      case Boolean: return "BOOLEAN";
      case Date: return "DATETIME";
      case Object:
      case Array: return "TEXT";
      case Buffer: return "BLOB";
      default: return "TEXT";
    }
  }
}
