import { Database } from "bun:sqlite";
import { z } from "zod";
import { createSchemaExtractor } from "../../src/database/schema/schema-extractor";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import {
  TableSchema,
  ColumnDefinition,
} from "../../src/database/base-controller";
const dbtemp = new Database(":memory:");
const dbinitializer = new DatabaseInitializer({ database: dbtemp });
await dbinitializer.initialize();
const schemas = dbinitializer.getSchemas(); //:TableSchema[]
/**
 * Función para extraer esquemas de una base de datos y generar validadores Zod
 */
export async function extractAndValidateSchemas(
  databasePath: string,
): Promise<Record<string, z.ZodObject<any>>> {
  // Crear extractor de esquemas
  const extractor = createSchemaExtractor(databasePath);

  // Extraer todos los esquemas de la base de datos
  const schemas = await extractor.extractAllSchemas();

  // Crear validadores para cada tabla
  const validators: Record<string, z.ZodObject<any>> = {};

  for (const { tableName, tableSchema } of schemas) {
    validators[tableName] = createZodValidatorFromTableSchema(tableSchema);
  }

  return validators;
}

/**
 * Función para generar validadores Zod a partir de esquemas ya existentes
 */
export function validateFromSchemas(
  schemas: TableSchema[],
): Record<string, z.ZodObject<any>> {
  const validators: Record<string, z.ZodObject<any>> = {};

  for (const tableSchema of schemas) {
    validators[tableSchema.tableName] =
      createZodValidatorFromTableSchema(tableSchema);
  }

  return validators;
}

/**
 * Crear un validador Zod a partir de un TableSchema
 */
function createZodValidatorFromTableSchema(
  tableSchema: TableSchema,
): z.ZodObject<any> {
  const schemaFields: Record<string, z.ZodTypeAny> = {};

  for (const column of tableSchema.columns) {
    let zodType: z.ZodTypeAny;

    // Mapear tipo de columna a tipo Zod
    switch (column.type) {
      case "INTEGER":
      case "SERIAL":
        zodType = z.number().int();
        break;
      case "REAL":
        zodType = z.number();
        break;
      case "TEXT":
        // Añadir validación especial para campos de email y contraseña
        if (column.name.toLowerCase().includes("email")) {
          zodType = z.string().email();
        } else if (column.name.toLowerCase().includes("password")) {
          zodType = z.string().min(8);
        } else {
          zodType = z.string();
        }
        break;
      case "BOOLEAN":
        zodType = z.boolean();
        break;
      case "DATETIME":
        zodType = z.string().datetime({ offset: true });
        break;
      case "BLOB":
        zodType = z.instanceof(Uint8Array).or(z.string());
        break;
      default:
        zodType = z.string();
        break;
    }

    // Aplicar restricciones de nulabilidad según las restricciones de la columna
    if (!column.notNull && !column.primaryKey) {
      zodType = zodType.nullable().optional();
    }

    // Aplicar valores por defecto
    if (column.defaultValue !== undefined) {
      if (column.defaultValue === "CURRENT_TIMESTAMP") {
        zodType = zodType.default(new Date().toISOString());
      } else if (
        column.defaultValue === true ||
        column.defaultValue === false
      ) {
        zodType = zodType.default(column.defaultValue);
      } else if (
        typeof column.defaultValue === "string" &&
        column.defaultValue.startsWith("'") &&
        column.defaultValue.endsWith("'")
      ) {
        // Quitar comillas simples si es un valor de cadena por defecto
        const stringValue = column.defaultValue.slice(1, -1);
        zodType = zodType.default(stringValue);
      } else {
        zodType = zodType.default(column.defaultValue);
      }
    }

    schemaFields[column.name] = zodType;
  }

  return z.object(schemaFields);
}

/**
 * Crear un validador Zod para crear (sin valores generados automáticamente)
 */
function createZodCreateValidatorFromTableSchema(
  tableSchema: TableSchema,
): z.ZodObject<any> {
  const schemaFields: Record<string, z.ZodTypeAny> = {};

  for (const column of tableSchema.columns) {
    let zodType: z.ZodTypeAny;

    // Mapear tipo de columna a tipo Zod
    switch (column.type) {
      case "INTEGER":
      case "SERIAL":
        zodType = z.number().int();
        break;
      case "REAL":
        zodType = z.number();
        break;
      case "TEXT":
        // Añadir validación especial para campos de email y contraseña
        if (column.name.toLowerCase().includes("email")) {
          zodType = z.string().email();
        } else if (column.name.toLowerCase().includes("password")) {
          zodType = z.string().min(8);
        } else {
          zodType = z.string();
        }
        break;
      case "BOOLEAN":
        zodType = z.boolean();
        break;
      case "DATETIME":
        zodType = z.string().datetime({ offset: true });
        break;
      case "BLOB":
        zodType = z.instanceof(Uint8Array).or(z.string());
        break;
      default:
        zodType = z.string();
        break;
    }

    // Para crear, omitir campos con valores por defecto generados automáticamente
    // como IDs con funciones como lower(hex(randomblob(16))) o CURRENT_TIMESTAMP
    if (
      column.defaultValue !== undefined &&
      (column.defaultValue === "CURRENT_TIMESTAMP" ||
        (typeof column.defaultValue === "string" &&
          column.defaultValue.includes("randomblob")))
    ) {
      continue; // Omitir este campo
    }

    // Aplicar restricciones de nulabilidad
    if (!column.notNull && !column.primaryKey) {
      zodType = zodType.nullable().optional();
    } else if (column.notNull && !column.primaryKey) {
      // Campos obligatorios (no null) para crear
      zodType = zodType;
    }

    // Aplicar valores por defecto (solo si no son generados automáticamente)
    if (column.defaultValue !== undefined) {
      if (
        column.defaultValue !== "CURRENT_TIMESTAMP" &&
        !(
          typeof column.defaultValue === "string" &&
          column.defaultValue.includes("randomblob")
        )
      ) {
        if (column.defaultValue === true || column.defaultValue === false) {
          zodType = zodType.default(column.defaultValue);
        } else if (
          typeof column.defaultValue === "string" &&
          column.defaultValue.startsWith("'") &&
          column.defaultValue.endsWith("'")
        ) {
          // Quitar comillas simples si es un valor de cadena por defecto
          const stringValue = column.defaultValue.slice(1, -1);
          zodType = zodType.default(stringValue);
        } else {
          zodType = zodType.default(column.defaultValue);
        }
      }
    }

    schemaFields[column.name] = zodType;
  }

  return z.object(schemaFields);
}

/**
 * Crear un validador Zod para actualizar (todos los campos opcionales)
 */
function createZodUpdateValidatorFromTableSchema(
  tableSchema: TableSchema,
): z.ZodObject<any> {
  const schemaFields: Record<string, z.ZodTypeAny> = {};

  for (const column of tableSchema.columns) {
    let zodType: z.ZodTypeAny;

    // Para actualizar, omitir campos primarios
    if (column.primaryKey) {
      continue;
    }

    // Mapear tipo de columna a tipo Zod
    switch (column.type) {
      case "INTEGER":
      case "SERIAL":
        zodType = z.number().int();
        break;
      case "REAL":
        zodType = z.number();
        break;
      case "TEXT":
        // Añadir validación especial para campos de email y contraseña
        if (column.name.toLowerCase().includes("email")) {
          zodType = z.string().email();
        } else if (column.name.toLowerCase().includes("password")) {
          zodType = z.string().min(8);
        } else {
          zodType = z.string();
        }
        break;
      case "BOOLEAN":
        zodType = z.boolean();
        break;
      case "DATETIME":
        zodType = z.string().datetime({ offset: true });
        break;
      case "BLOB":
        zodType = z.instanceof(Uint8Array).or(z.string());
        break;
      default:
        zodType = z.string();
        break;
    }

    // Para actualizar, todos los campos son opcionales
    zodType = zodType.nullable().optional();

    schemaFields[column.name] = zodType;
  }

  return z.object(schemaFields);
}
export {
  createZodValidatorFromTableSchema,
  createZodCreateValidatorFromTableSchema,
  createZodUpdateValidatorFromTableSchema,
};
