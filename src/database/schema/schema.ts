import type {
  ColumnDefinition,
  ColumnType,
  TableSchema,
} from "../base-controller.ts";
import { z } from "zod";
import { mapSqlTypeToZodType, mapConstructorToZodType, ConstructorType } from "./zod-mapping";

// Tipos para tipado dinámico
export type ConstructorToZodType<T> =
  T extends StringConstructor ? z.ZodString :
  T extends NumberConstructor ? z.ZodNumber :
  T extends BooleanConstructor ? z.ZodBoolean :
  T extends DateConstructor ? z.ZodDate :
  T extends ObjectConstructor ? z.ZodRecord<z.ZodString, z.ZodAny> :
  T extends ArrayConstructor ? z.ZodArray<z.ZodAny> :
  T extends BufferConstructor ? z.ZodAny :
  z.ZodAny;

export type SchemaOptionsToZodType<T> =
  T extends { type: infer Type; notNull: true } ? ConstructorToZodType<Type> :
  T extends { type: infer Type; required: true } ? ConstructorToZodType<Type> :
  T extends { type: infer Type; primaryKey: true } ? ConstructorToZodType<Type> :
  T extends { type: infer Type } ? z.ZodOptional<ConstructorToZodType<Type>> :
  T extends ConstructorType ? z.ZodOptional<ConstructorToZodType<T>> :
  z.ZodOptional<z.ZodAny>;

// Inferir la forma completa del schema
type InferSchemaShape<T extends SchemaDefinition> = {
  [K in keyof T]: SchemaOptionsToZodType<T[K]>;
};

// Tipos para create, update y read
type InferCreateShape<T extends SchemaDefinition> = {
  [K in keyof T]:
  T[K] extends { primaryKey: true } ? z.ZodOptional<SchemaOptionsToZodType<T[K]>> :
  T[K] extends { default: any } ? z.ZodOptional<SchemaOptionsToZodType<T[K]>> :
  SchemaOptionsToZodType<T[K]>;
};

type InferUpdateShape<T extends SchemaDefinition> = {
  [K in keyof T]: z.ZodOptional<SchemaOptionsToZodType<T[K]>>;
};

// Interface para schemas Zod tipados
export interface TypedModelZodSchemas<T extends SchemaDefinition> {
  create: z.ZodObject<InferCreateShape<T>>;
  update: z.ZodObject<InferUpdateShape<T>>;
  read: z.ZodObject<InferSchemaShape<T>>;
}

export interface ModelZodSchemas {
  create: z.ZodObject<any>;
  update: z.ZodObject<any>;
  read: z.ZodObject<any>;
}

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
  onDelete?: "CASCADE" | "SET NULL" | "RESTRICT" | "NO ACTION";
  autoIncrement?: boolean;
}

export type SchemaField =
  | ConstructorType
  | SchemaTypeOptions
  | { [key: string]: SchemaField }
  | SchemaField[];

export interface SchemaDefinition {
  [key: string]: SchemaField;
}

export class Schema<T extends SchemaDefinition = SchemaDefinition> {
  private definition: T;
  private options: SchemaOptions;

  // Store the definition type for type inference
  readonly __definitionType!: T;

  constructor(definition: T, options: SchemaOptions = {}) {
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

  public getDefinition(): T {
    return this.definition;
  }

  public getOptions(): SchemaOptions {
    return this.options;
  }

  /**
   * Generates Zod schemas (create, update, read) from the schema definition
   */
  public toZod(): ModelZodSchemas {
    const shape = this.parseZodShape(this.definition);
    const baseSchema = z.object(shape);

    const createShape: Record<string, z.ZodTypeAny> = {};
    const updateShape: Record<string, z.ZodTypeAny> = {};
    const readShape: Record<string, z.ZodTypeAny> = { ...shape };

    for (const [key, field] of Object.entries(this.definition)) {
      const zodType = this.mapFieldToZod(field);

      let isRequiredForCreate = false; // Default to optional (nullable in SQL defaults to NULL if omitted)

      if (!this.isConstructor(field) && typeof field === "object" && !Array.isArray(field)) {
        const opts = field as SchemaTypeOptions;
        // If explicitly required or notNull or primaryKey, set to required
        if (opts.required || opts.notNull) {
          isRequiredForCreate = true;
        }

        // Override if default exists (can be omitted)
        if (opts.default !== undefined) {
          isRequiredForCreate = false;
        }
        // Primary Key is usually auto-generated
        if (opts.primaryKey) {
          isRequiredForCreate = false;
        }
      }

      createShape[key] = isRequiredForCreate ? zodType : zodType.optional();
      updateShape[key] = zodType.optional();
    }

    return {
      create: z.object(createShape),
      update: z.object(updateShape),
      read: baseSchema,
    };
  }

  /**
   * Generates typed Zod schemas with strong type inference
   * Uses the class's generic type parameter for automatic type inference
   */
  public toZodTyped(): TypedModelZodSchemas<T> {
    const baseSchemas = this.toZod();

    // Type assertion to preserve type information
    return {
      create: baseSchemas.create as TypedModelZodSchemas<T>['create'],
      update: baseSchemas.update as TypedModelZodSchemas<T>['update'],
      read: baseSchemas.read as TypedModelZodSchemas<T>['read'],
    };
  }

  private parseZodShape(definition: SchemaDefinition): Record<string, z.ZodTypeAny> {
    const shape: Record<string, z.ZodTypeAny> = {};
    for (const [key, value] of Object.entries(definition)) {
      shape[key] = this.mapFieldToZod(value);
    }
    return shape;
  }

  private mapFieldToZod(field: SchemaField): z.ZodTypeAny {
    if (this.isConstructor(field)) {
      // Raw constructor implies nullable in our system (no notNull flag)
      return this.mapConstructorToZod(field as ConstructorType).nullable();
    }

    if (Array.isArray(field)) {
      if (field.length > 0) {
        return z.array(this.mapFieldToZod(field[0]));
      }
      return z.array(z.any());
    }

    if (typeof field === "object" && field !== null) {
      if ((field).type && (this.isConstructor((field).type) || typeof (field).type === 'string')) {
        const options = field as SchemaTypeOptions;
        let zodType = this.mapConstructorToZod(options.type);

        if (options.check) {
          // checks ignored for Zod types currently
        }

        // Apply nullable if NOT (required OR notNull OR primaryKey)
        if (!options.notNull && !options.required && !options.primaryKey) {
          zodType = zodType.nullable();
        }

        return zodType;
      } else {
        const shape = this.parseZodShape(field as SchemaDefinition);
        return z.object(shape);
      }
    }

    return z.any();
  }

  private mapConstructorToZod(type: ConstructorType | ColumnType): z.ZodTypeAny {
    if (typeof type === 'string') {
      return mapSqlTypeToZodType(type);
    }
    return mapConstructorToZodType(type);
  }

  public static fromTableSchema(tableSchema: TableSchema): Schema<SchemaDefinition> {
    const definition: SchemaDefinition = {};
    const options: SchemaOptions = {};

    for (const column of tableSchema.columns) {
      definition[column.name] = this.convertColumnToSchemaField(column);
    }

    if (tableSchema.indexes && tableSchema.indexes.length > 0) {
      options.indexes = tableSchema.indexes.map((index) => ({
        name: index.name,
        columns: index.columns,
        unique: index.unique,
      }));
    }

    return new Schema(definition, options);
  }

  public equals(other: Schema, tableName: string = "test"): boolean {
    const thisTableSchema = this.toTableSchema(tableName);
    const otherTableSchema = other.toTableSchema(tableName);

    return this.compareTableSchemas(thisTableSchema, otherTableSchema);
  }

  public static compareTableSchemas(
    schema1: TableSchema,
    schema2: TableSchema,
  ): boolean {
    if (schema1.tableName !== schema2.tableName) {
      return false;
    }

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
      field.required = true;
    } else if (column.notNull) {
      field.required = true;
    }

    if (column.unique) {
      field.unique = true;
    }

    if (column.check) {
      field.check = column.check;
    }

    if (column.onDelete) {
      field.onDelete = column.onDelete;
    }

    if (column.defaultValue !== undefined) {
      if (column.defaultValue === "CURRENT_TIMESTAMP") {
        field.default = Date.now;
      } else if (
        typeof column.defaultValue === "object" &&
        column.defaultValue !== null
      ) {
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
        return type;
    }
  }

  private static compareColumns(
    col1: ColumnDefinition,
    col2: ColumnDefinition,
  ): boolean {
    if (col1.name !== col2.name || col1.type !== col2.type) {
      return false;
    }

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

    if (col1.defaultValue !== col2.defaultValue) {
      if (
        col1.defaultValue === "CURRENT_TIMESTAMP" &&
        col2.defaultValue === "CURRENT_TIMESTAMP"
      ) {
      } else if (
        col1.defaultValue === Date.now &&
        col2.defaultValue === Date.now
      ) {
      } else if (
        typeof col1.defaultValue === "object" &&
        typeof col2.defaultValue === "object"
      ) {
        if (
          JSON.stringify(col1.defaultValue) !==
          JSON.stringify(col2.defaultValue)
        ) {
          return false;
        }
      } else {
        return false;
      }
    }

    if (col1.check !== col2.check) {
      return false;
    }

    if (col1.references && col2.references) {
      if (
        col1.references.table !== col2.references.table ||
        col1.references.column !== col2.references.column
      ) {
        return false;
      }
    } else if (col1.references || col2.references) {
      return false;
    }

    if (col1.onDelete !== col2.onDelete) {
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
        sqlColumn.notNull = true;
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

      if (value.onDelete) {
        sqlColumn.onDelete = value.onDelete;
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

/**
 * Helper function para crear schemas con tipado fuerte de forma más concisa
 */
export function createTypedSchema<T extends SchemaDefinition>(
  definition: T,
  options: SchemaOptions = {}
): Schema<T> {
  return new Schema(definition, options);
}

/**
 * Type helpers para usar directamente en el código
 * Estos helpers extraen los tipos correctamente de los schemas Zod
 * 
 * Ahora funcionan correctamente porque Schema es genérico y preserva
 * la información del tipo de definición.
 */
export type InferTypedSchemaRead<T extends Schema<any>> =
  T extends Schema<infer D> ? z.infer<TypedModelZodSchemas<D>['read']> : never;

export type InferTypedSchemaCreate<T extends Schema<any>> =
  T extends Schema<infer D> ? z.infer<TypedModelZodSchemas<D>['create']> : never;

export type InferTypedSchemaUpdate<T extends Schema<any>> =
  T extends Schema<infer D> ? z.infer<TypedModelZodSchemas<D>['update']> : never;

/**
 * Helper para crear type assertions cuando se necesita más control
 * @deprecated Use Schema<T> directamente con toZodTyped() en su lugar
 */
export function asTypedSchema<T extends SchemaDefinition>(
  schema: Schema<T>,
  _definition: T
): TypedModelZodSchemas<T> {
  const zodSchemas = schema.toZodTyped();

  return {
    create: zodSchemas.create as TypedModelZodSchemas<T>['create'],
    update: zodSchemas.update as TypedModelZodSchemas<T>['update'],
    read: zodSchemas.read as TypedModelZodSchemas<T>['read'],
  };
}
