// Core Schema Module - No predefined schemas
// This module exports only the Schema class and related utilities

export { Schema } from "./schema";
export type {
  SchemaDefinition,
  SchemaField,
  SchemaOptions,
  SchemaIndex,
  SchemaTypeOptions,
  ModelZodSchemas,
  TypedModelZodSchemas,
  InferTypedSchemaRead,
  InferTypedSchemaCreate,
  InferTypedSchemaUpdate,
} from "./schema";
export { createTypedSchema, asTypedSchema } from "./schema";

// Export zod mapping utilities
export {
  mapSqlTypeToZodType,
  mapConstructorToZodType,
  flexibleBoolean,
} from "./zod-mapping";
export type { ConstructorType } from "./zod-mapping";

// Export constants for schema building
export { StandardFields } from "./constants";