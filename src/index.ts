// src/index.ts
export * from "./logger";
export * from "./services";
export * from "./database";
export * from "./types/auth";
export * from "./types/oauth";
export * from "./types/index";

// Reexportar Zod para conveniencia de usuarios y control de versiones
// Usamos export * con exclusión para evitar conflicto con la clase Schema
export * as zod from "zod";
export { z as z } from "zod";

// Reexportar tipos más comunes de forma explícita
export type {
  ZodSchema,
  ZodType,
  ZodObject,
  ZodTypeAny
} from "zod";
export * from "./database/config";
export * from "./database/schema/schema-builder";
export * from "./database/schema/oauth-schema-extensions";
export * from "./database/schema/schema";
export * from "./database/schema/schema-extractor";
export * from "./database/schema/migration-generator";
export * from "./database/schema/schema-comparison";
