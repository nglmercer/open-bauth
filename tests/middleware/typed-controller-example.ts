// Ejemplo de cómo usar el controlador tipado con Zod schemas para mejor autocompletado y type safety

import { z } from "zod";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import type { MiddlewareTestContext } from "./setup";

// Definir un schema Zod para el usuario
const UserSchema = z.object({
  id: z.number(),
  username: z.string(),
  email: z.string().email(),
  first_name: z.string().optional(),
  last_name: z.string().optional(),
  is_active: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

// Tipo inferido del schema
type User = z.infer<typeof UserSchema>;

// Ejemplo de función con tipado completo
export async function updateUserWithTypeSafety(
  context: MiddlewareTestContext,
  userId: number,
  updates: Partial<Pick<User, 'first_name' | 'last_name' | 'email' | 'is_active'>>
): Promise<User> {
  const { dbInitializer } = context;
  
  // El controlador ahora tiene tipado completo
  const userController = dbInitializer.createController<User>("users");
  
  // ✅ Autocompletado funciona aquí - TypeScript sabe que updates puede tener:
  // - first_name?: string
  // - last_name?: string  
  // - email?: string
  // - is_active?: boolean
  
  const result = await userController.update(userId, updates);
  
  if (!result.success || !result.data) {
    throw new Error(`Failed to update user: ${result.error}`);
  }
  
  // ✅ TypeScript sabe que result.data es de tipo User
  return result.data;
}

// Ejemplo de búsqueda con tipado
export async function findActiveUsers(
  context: MiddlewareTestContext,
  limit: number = 10
): Promise<User[]> {
  const { dbInitializer } = context;
  
  const userController = dbInitializer.createController<User>("users");
  
  // ✅ TypeScript infiere el tipo de los parámetros where
  const result = await userController.findAll({
    where: { 
      is_active: true  // ✅ Autocompletado sugiere 'is_active'
    },
    limit,
    orderBy: "created_at",
    orderDirection: "DESC"
  });
  
  if (!result.success || !result.data) {
    throw new Error(`Failed to find users: ${result.error}`);
  }
  
  // ✅ TypeScript sabe que result.data es User[]
  return result.data;
}

// Ejemplo de creación con validación
export async function createUserWithValidation(
  context: MiddlewareTestContext,
  userData: {
    username: string;
    email: string;
    first_name?: string;
    last_name?: string;
  }
): Promise<User> {
  const { dbInitializer } = context;
  
  const userController = dbInitializer.createController<User>("users");
  
  // ✅ TypeScript valida que userData tenga las propiedades requeridas
  const result = await userController.create({
    ...userData,
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  
  if (!result.success || !result.data) {
    throw new Error(`Failed to create user: ${result.error}`);
  }
  
  return result.data;
}

// Ejemplo de uso de relaciones con tipado
export async function getUserWithRoles(
  context: MiddlewareTestContext,
  userId: number
): Promise<User & { roles?: Array<{ name: string; description: string }> }> {
  const { dbInitializer } = context;
  
  const userController = dbInitializer.createController<User>("users");
  
  // ✅ Uso de joins con tipado
  const result = await userController.findByIdWithRelations(
    userId,
    [
      {
        table: "user_roles",
        on: `"users"."id" = "user_roles"."user_id"`,
        type: "LEFT"
      },
      {
        table: "roles", 
        on: `"user_roles"."role_id" = "roles"."id"`,
        type: "LEFT",
        select: ["name", "description"]
      }
    ],
    ["id", "username", "email", "is_active"] // Seleccionar columnas específicas
  );
  
  if (!result.success || !result.data) {
    throw new Error(`Failed to find user with roles: ${result.error}`);
  }
  
  return result.data as User & { roles?: Array<{ name: string; description: string }> };
}

// Ventajas de este enfoque:
// 1. ✅ Autocompletado inteligente en VSCode
// 2. ✅ Validación en tiempo de compilación
// 3. ✅ Documentación automática de tipos
// 4. ✅ Refactoring seguro
// 5. ✅ Menos errores en tiempo de ejecución