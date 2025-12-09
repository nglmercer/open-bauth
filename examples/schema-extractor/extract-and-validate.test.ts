import { Database } from "bun:sqlite";
import { beforeAll, afterAll, describe, expect, it } from "bun:test";
import { DatabaseInitializer } from "../../src/database/database-initializer";
import {
  validateFromSchemas,
  createZodCreateValidatorFromTableSchema,
  createZodUpdateValidatorFromTableSchema,
} from "./extract-and-validate";

describe("extract-and-validate", () => {
  // Inicializar base de datos en memoria y esquemas antes de las pruebas
  let db: Database;
  let dbInitializer: DatabaseInitializer;
  let schemas: import("../../src/database/base-controller").TableSchema[];

  beforeAll(async () => {
    db = new Database(":memory:");
    dbInitializer = new DatabaseInitializer({ database: db });
    await dbInitializer.initialize();
    schemas = dbInitializer.getSchemas();
  });

  afterAll(() => {
    db.close();
  });

  describe("validateFromSchemas", () => {
    it("debería generar validadores para todos los esquemas", () => {
      const validators = validateFromSchemas(schemas);

      // Verificar que se generaron validadores para todas las tablas
      expect(validators).toBeDefined();
      expect(validators.users).toBeDefined();
      expect(validators.roles).toBeDefined();
      expect(validators.permissions).toBeDefined();
      expect(validators.user_roles).toBeDefined();
      expect(validators.role_permissions).toBeDefined();
      expect(validators.sessions).toBeDefined();
    });

    it("debería validar correctamente datos de usuario", () => {
      const validators = validateFromSchemas(schemas);
      const usersValidator = validators.users;

      if (!usersValidator) throw new Error("Validator for users not found");

      // Datos válidos
      const validUserData = {
        email: "usuario@example.com",
        username: "usuario123",
        password_hash: "hash_secreto_123",
        first_name: "Usuario",
        last_name: "Ejemplo",
      };

      const result = usersValidator.safeParse(validUserData);
      expect(result.success).toBe(true);
    });

    it("debería rechazar datos de usuario inválidos", () => {
      const validators = validateFromSchemas(schemas);
      const usersValidator = validators.users;

      if (!usersValidator) throw new Error("Validator for users not found");

      // Datos inválidos
      const invalidUserData = {
        email: "email-no-valido", // Email inválido
        password_hash: "123", // Contraseña demasiado corta
        // Faltan campos requeridos
      };

      const result = usersValidator.safeParse(invalidUserData);
      expect(result.success).toBe(false);
      if (!result.success) {
        const issues = result.error.issues;
        expect(issues.some((issue) => issue.path[0] === "email")).toBe(true);
        expect(issues.some((issue) => issue.path[0] === "password_hash")).toBe(
          true,
        );
      }
    });
  });

  describe("createZodCreateValidatorFromTableSchema", () => {
    it("debería crear un validador para inserción de usuarios", () => {
      const userSchema = schemas.find((s) => s.tableName === "users");
      if (!userSchema) throw new Error("User schema not found");

      const createValidator =
        createZodCreateValidatorFromTableSchema(userSchema);

      // Datos válidos para crear
      const validCreateData = {
        email: "nuevo@example.com",
        username: "nuevo_usuario",
        password_hash: "contraseña_segura_123",
        first_name: "Nuevo",
        last_name: "Usuario",
      };

      const result = createValidator.safeParse(validCreateData);
      expect(result.success).toBe(true);
    });

    it("debería omitir campos con valores por defecto generados automáticamente", () => {
      const userSchema = schemas.find((s) => s.tableName === "users");
      if (!userSchema) throw new Error("User schema not found");

      const createValidator =
        createZodCreateValidatorFromTableSchema(userSchema);

      // Solo datos necesarios para crear, sin ID ni timestamps
      const minimalData = {
        email: "minimal@example.com",
        password_hash: "contraseña_segura_123",
      };

      const result = createValidator.safeParse(minimalData);
      expect(result.success).toBe(true);
    });

    it("debería omitir el campo ID con valor por defecto generado automáticamente", () => {
      const userSchema = schemas.find((s) => s.tableName === "users");
      if (!userSchema) throw new Error("User schema not found");

      const createValidator =
        createZodCreateValidatorFromTableSchema(userSchema);

      // Verificar que el campo ID no está presente en el validador de creación
      const shapeKeys = Object.keys(createValidator._def.shape);
      expect(shapeKeys.includes("id")).toBe(false);

      // Verificar que los campos generados automáticamente tampoco están presentes
      expect(shapeKeys.includes("created_at")).toBe(false);
      expect(shapeKeys.includes("updated_at")).toBe(false);
    });
  });

  describe("createZodUpdateValidatorFromTableSchema", () => {
    it("debería crear un validador para actualización de usuarios", () => {
      const userSchema = schemas.find((s) => s.tableName === "users");
      if (!userSchema) throw new Error("User schema not found");

      const updateValidator =
        createZodUpdateValidatorFromTableSchema(userSchema);

      // Datos para actualizar (opcional y sin primary key)
      const updateData = {
        first_name: "Nombre Actualizado",
      };

      const result = updateValidator.safeParse(updateData);
      expect(result.success).toBe(true);
    });

    it("debería omitir campos primarios en el validador de actualización", () => {
      const userSchema = schemas.find((s) => s.tableName === "users");
      if (!userSchema) throw new Error("User schema not found");

      const updateValidator =
        createZodUpdateValidatorFromTableSchema(userSchema);

      // Verificar que el campo ID no está presente en el validador
      const shapeKeys = Object.keys(updateValidator._def.shape);
      expect(shapeKeys.includes("id")).toBe(false);
    });
  });
});
