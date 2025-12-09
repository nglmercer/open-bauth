// src/index.ts
export * from "./middleware/auth";
export * from "./logger";
export * from "./services";
export * from "./database";
export * from "./types/auth";
export * from "./types/oauth";

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
