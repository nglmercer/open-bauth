import type {
  ColumnDefinition,
  ColumnType,
  TableSchema,
} from "../base-controller.ts";

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
      indexes: indexes.length > 0 ? indexes : undefined,
    };
  }

  public getColumns(): ColumnDefinition[] {
    return this.parseColumns();
  }

  public getDefinition(): SchemaDefinition {
    return this.definition;
  }

  public getOptions(): SchemaOptions {
    return this.options;
  }

  /**
   * Convierte un TableSchema a una instancia de Schema
   */
  public static fromTableSchema(tableSchema: TableSchema): Schema {
    const definition: SchemaDefinition = {};
    const options: SchemaOptions = {};

    // Convertir columnas a definición de schema
    for (const column of tableSchema.columns) {
      definition[column.name] = this.convertColumnToSchemaField(column);
    }

    // Convertir índices a opciones
    if (tableSchema.indexes && tableSchema.indexes.length > 0) {
      options.indexes = tableSchema.indexes.map((index) => ({
        name: index.name,
        columns: index.columns,
        unique: index.unique,
      }));
    }

    return new Schema(definition, options);
  }

  /**
   * Compara dos schemas para verificar si son equivalentes
   */
  public equals(other: Schema, tableName: string = "test"): boolean {
    const thisTableSchema = this.toTableSchema(tableName);
    const otherTableSchema = other.toTableSchema(tableName);

    return this.compareTableSchemas(thisTableSchema, otherTableSchema);
  }

  /**
   * Compara dos TableSchemas para verificar si son equivalentes
   */
  public static compareTableSchemas(
    schema1: TableSchema,
    schema2: TableSchema,
  ): boolean {
    // Comparar tableName
    if (schema1.tableName !== schema2.tableName) {
      return false;
    }

    // Comparar columnas
    if (schema1.columns.length !== schema2.columns.length) {
      return false;
    }

    for (const col1 of schema1.columns) {
      const col2 = schema2.columns.find((c) => c.name === col1.name);
      if (!col2) {
        return false;
      }

      if (!this.compareColumns(col1, col2)) {
        return false;
      }
    }

    // Comparar índices
    const indexes1 = schema1.indexes || [];
    const indexes2 = schema2.indexes || [];

    if (indexes1.length !== indexes2.length) {
      return false;
    }

    for (const idx1 of indexes1) {
      const idx2 = indexes2.find((i) => i.name === idx1.name);
      if (!idx2) {
        return false;
      }

      if (
        idx1.columns.length !== idx2.columns.length ||
        !idx1.columns.every((col) => idx2.columns.includes(col)) ||
        idx1.unique !== idx2.unique
      ) {
        return false;
      }
    }

    return true;
  }

  private static convertColumnToSchemaField(
    column: ColumnDefinition,
  ): SchemaField {
    const field: SchemaTypeOptions = {
      type: this.mapSQLToConstructor(column.type),
    };

    if (column.primaryKey) {
      field.primaryKey = true;
      field.required = true; // primaryKey implica required
    } else if (column.notNull) {
      field.required = true;
    }

    if (column.unique) {
      field.unique = true;
    }

    if (column.check) {
      field.check = column.check;
    }

    if (column.defaultValue !== undefined) {
      if (column.defaultValue === "CURRENT_TIMESTAMP") {
        field.default = Date.now;
      } else if (
        typeof column.defaultValue === "object" &&
        column.defaultValue !== null
      ) {
        // Para objetos, hacer una copia profunda para evitar problemas de referencia
        field.default = JSON.parse(JSON.stringify(column.defaultValue));
      } else {
        field.default = column.defaultValue;
      }
    }

    if (column.references) {
      field.references = column.references;
    }

    return field;
  }

  private static mapSQLToConstructor(
    type: ColumnType,
  ): ConstructorType | ColumnType {
    switch (type) {
      case "TEXT":
      case "VARCHAR":
        return String;
      case "INTEGER":
      case "SERIAL":
        return Number;
      case "BOOLEAN":
      case "BIT":
        return Boolean;
      case "REAL":
        return Number;
      case "DATE":
      case "DATETIME":
        return Date;
      case "BLOB":
        return Buffer;
      default:
        return type; // Retornar el tipo string si no hay mapeo directo
    }
  }

  private static compareColumns(
    col1: ColumnDefinition,
    col2: ColumnDefinition,
  ): boolean {
    // Comparar propiedades básicas
    if (col1.name !== col2.name || col1.type !== col2.type) {
      return false;
    }

    // Comparar booleanos
    const boolProps: (keyof ColumnDefinition)[] = [
      "primaryKey",
      "notNull",
      "unique",
    ];
    for (const prop of boolProps) {
      if (col1[prop] !== col2[prop]) {
        return false;
      }
    }

    // Comparar defaultValue
    if (col1.defaultValue !== col2.defaultValue) {
      // Manejar casos especiales como CURRENT_TIMESTAMP
      if (
        col1.defaultValue === "CURRENT_TIMESTAMP" &&
        col2.defaultValue === "CURRENT_TIMESTAMP"
      ) {
        // OK, son iguales
      } else if (
        col1.defaultValue === Date.now &&
        col2.defaultValue === Date.now
      ) {
        // OK, son iguales
      } else if (
        typeof col1.defaultValue === "object" &&
        typeof col2.defaultValue === "object"
      ) {
        // Comparar objetos usando JSON.stringify
        if (
          JSON.stringify(col1.defaultValue) !==
          JSON.stringify(col2.defaultValue)
        ) {
          return false;
        }
        // OK, los objetos son iguales
      } else {
        return false;
      }
    }

    // Comparar check
    if (col1.check !== col2.check) {
      return false;
    }

    // Comparar references
    if (col1.references && col2.references) {
      if (
        col1.references.table !== col2.references.table ||
        col1.references.column !== col2.references.column
      ) {
        return false;
      }
    } else if (col1.references || col2.references) {
      // Uno tiene references y el otro no
      return false;
    }

    return true;
  }

  private compareTableSchemas(
    schema1: TableSchema,
    schema2: TableSchema,
  ): boolean {
    return Schema.compareTableSchemas(schema1, schema2);
  }

  private parseColumns(): ColumnDefinition[] {
    return Object.entries(this.definition).map(([name, value]) =>
      this.parseField(name, value),
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

    if (
      typeof value === "object" &&
      !value.type &&
      !this.isConstructor(value)
    ) {
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
        } else if (typeof value.default === "function") {
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
    return [String, Number, Boolean, Date, Object, Array, Buffer].includes(
      value,
    );
  }

  private mapConstructorToSQL(type: any): ColumnType {
    if (typeof type === "string") return type as ColumnType;

    switch (type) {
      case String:
        return "TEXT";
      case Number:
        return "INTEGER";
      case Boolean:
        return "BOOLEAN";
      case Date:
        return "DATETIME";
      case Object:
      case Array:
        return "TEXT";
      case Buffer:
        return "BLOB";
      default:
        return "TEXT";
    }
  }
}
