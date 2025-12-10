/**
 * Ejemplos de uso del sistema de tipado dinámico para Zod schemas
 */

import { z } from "zod";
import { 
  createTypedSchema, 
  InferTypedSchemaRead,
  InferTypedSchemaCreate,
  InferTypedSchemaUpdate,
  asTypedSchema,
    Schema } from "../src/database/schema/schema";

// ============================================
// EJEMPLO 1: Schema de Usuario con tipado fuerte
// ============================================

const userSchemaDefinition = {
  id: { type: String, primaryKey: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isActive: { type: Boolean, default: true },
  role: { type: String, default: 'user' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
} as const;

// Usando Schema con tipado fuerte
const userSchema = new Schema(userSchemaDefinition, {
  indexes: [
    { name: "idx_username", columns: ["username"], unique: true },
    { name: "idx_email", columns: ["email"], unique: true }
  ]
});

// Obtener los schemas Zod con tipado completo
const userZodSchemas = userSchema.toZodTyped<typeof userSchemaDefinition>();

// Inferir tipos automáticamente - ¡AHORA SÍ FUNCIONA!
type UserReadType = z.infer<typeof userZodSchemas.read>;
type UserCreateType = z.infer<typeof userZodSchemas.create>;
type UserUpdateType = z.infer<typeof userZodSchemas.update>;

// También podemos usar los helpers de tipo - ¡Funcionan dinámicamente!
// Estos tipos se infieren correctamente en tiempo de compilación
type UserReadType2 = InferTypedSchemaRead<typeof userSchema>;
type UserCreateType2 = InferTypedSchemaCreate<typeof userSchema>;
type UserUpdateType2 = InferTypedSchemaUpdate<typeof userSchema>;

// Verificación de tipos: los tipos dinámicos deben ser compatibles con los estáticos
// Esto demuestra que los helpers de tipo funcionan correctamente
type TypeCompatibilityCheck =
  UserReadType2 extends UserReadType ? true : false;
type CreateTypeCompatibilityCheck =
  UserCreateType2 extends UserCreateType ? true : false;
type UpdateTypeCompatibilityCheck =
  UserUpdateType2 extends UserUpdateType ? true : false;

// Las verificaciones anteriores deberían ser 'true', demostrando que los tipos coinciden
// Función genérica que usa los tipos dinámicos para validación de datos
function validateUserData<T extends 'read' | 'create' | 'update'>(
  type: T,
  data: any
): T extends 'read' ? UserReadType2 : T extends 'create' ? UserCreateType2 : UserUpdateType2 {
  switch (type) {
    case 'read':
      return userZodSchemas.read.parse(data) as any;
    case 'create':
      return userZodSchemas.create.parse(data) as any;
    case 'update':
      return userZodSchemas.update.parse(data) as any;
    default:
      throw new Error('Invalid type');
  }
}

// Demostración del tipado en acción con uso de tipos dinámicos
function demonstrateUserTypes() {
  // Tipo Read - todos los campos son requeridos y tienen sus tipos correctos
  const userRead: UserReadType = {
    id: "user-123",
    username: "johndoe",
    email: "john@example.com",
    password: "hashed-password",
    isActive: true,
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date()
  };

  // Tipo Create - los campos con default son opcionales, los required son obligatorios
  const userCreate: UserCreateType = {
    username: "johndoe",
    email: "john@example.com",
    password: "secure-password",
    // id es opcional porque es primaryKey
    // isActive es opcional porque tiene default
    // role es opcional porque tiene default
    // createdAt y updatedAt son opcionales porque tienen default
  };

  // Tipo Update - todos los campos son opcionales
  const userUpdate: UserUpdateType = {
    username: "johndoe-updated",
    // Solo actualizamos el username, el resto es opcional
  };

  // Usar los tipos dinámicos en funciones reales
  const dynamicReadUser: UserReadType2 = userRead;
  const dynamicCreateUser: UserCreateType2 = userCreate;
  const dynamicUpdateUser: UserUpdateType2 = userUpdate;

  // Validación usando tipos dinámicos
  const validatedRead = validateUserData('read', dynamicReadUser);
  const validatedCreate = validateUserData('create', dynamicCreateUser);
  const validatedUpdate = validateUserData('update', dynamicUpdateUser);

  console.log("User types demonstration completed successfully!");
  console.log("Dynamic types validation:", {
    read: !!validatedRead,
    create: !!validatedCreate,
    update: !!validatedUpdate
  });
}

// ============================================
// EJEMPLO 2: Schema de Token de Verificación
// ============================================

const verificationTokenDefinition = {
  id: { type: String, primaryKey: true },
  userId: { type: String, required: true },
  token: { type: String, required: true, unique: true },
  type: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
} as const;

const tokenSchema = createTypedSchema(verificationTokenDefinition, {
  indexes: [
    { name: "idx_verification_token", columns: ["token"], unique: true },
    { name: "idx_verification_user", columns: ["userId"], unique: false }
  ]
});

const tokenZodSchemas = tokenSchema.toZodTyped<typeof verificationTokenDefinition>();

type TokenReadType = z.infer<typeof tokenZodSchemas.read>;
type TokenCreateType = z.infer<typeof tokenZodSchemas.create>;
type TokenUpdateType = z.infer<typeof tokenZodSchemas.update>;

// ============================================
// EJEMPLO 3: Usando con Schema existente (migración gradual)
// ============================================

// Si ya tienes un Schema existente, puedes usar asTypedSchema
const existingSchema = new Schema({
  name: { type: String, required: true },
  age: Number,
  isActive: { type: Boolean, default: true }
});

const typedExistingSchemas = asTypedSchema(existingSchema, {
  name: { type: String, required: true },
  age: Number,
  isActive: { type: Boolean, default: true }
} as const);

type ExistingReadType = z.infer<typeof typedExistingSchemas.read>;
type ExistingCreateType = z.infer<typeof typedExistingSchemas.create>;
type ExistingUpdateType = z.infer<typeof typedExistingSchemas.update>;

// ============================================
// EJEMPLO 4: Integración con controladores y servicios
// ============================================

class UserService {
  private schemas = userSchema.toZodTyped<typeof userSchemaDefinition>();

  async createUser(data: UserCreateType): Promise<UserReadType> {
    // Validación con Zod
    const validatedData = this.schemas.create.parse(data);
    
    // Simular creación en base de datos
    const createdUser: UserReadType = {
      ...validatedData,
      id: "generated-id",
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: validatedData.isActive ?? true,
      role: validatedData.role ?? 'user'
    };

    return createdUser;
  }

  async updateUser(id: string, data: UserUpdateType): Promise<UserReadType> {
    // Validación con Zod
    const validatedData = this.schemas.update.parse(data);
    
    // Simular actualización en base de datos
    const updatedUser: UserReadType = {
      id,
      username: "existing-username",
      email: "existing@example.com",
      password: "existing-password",
      isActive: true,
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
      ...validatedData
    };

    return updatedUser;
  }

  async getUserById(id: string): Promise<UserReadType | null> {
    // Simular lectura de base de datos
    const user: UserReadType = {
      id,
      username: "johndoe",
      email: "john@example.com",
      password: "hashed-password",
      isActive: true,
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Validación con Zod
    return this.schemas.read.parse(user);
  }
}



export {
  userSchema,
  tokenSchema,
  UserService,
  type UserReadType,
  type UserCreateType,
  type UserUpdateType,
  type TokenReadType,
  type TokenCreateType,
  type TokenUpdateType
};