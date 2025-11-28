/**
 * Script de migración avanzado y completo
 * Extiende el esquema de la librería y maneja migraciones complejas.
 */

import { Database } from "bun:sqlite";
import {
  DatabaseMigrationManager,
  type TableMigration,
  SPANISH_MAPPINGS,
} from "./database-migration-system";
import { DatabaseInitializer, type TableSchema } from "../src/index";

const DATABASE_PATH = "database.db";

// --- PASO 1: DEFINIR EL ESQUEMA EXTENDIDO ---
// Esta es nuestra tabla personalizada para guardar los datos extra.
const userProfileSchema: TableSchema = {
  tableName: "user_profiles",
  columns: [
    {
      name: "id",
      type: "TEXT",
      primaryKey: true,
      defaultValue: "(lower(hex(randomblob(16))))",
    },
    {
      name: "user_id",
      type: "TEXT",
      notNull: true,
      unique: true,
      references: { table: "users", column: "id" },
    },
    { name: "username", type: "TEXT", unique: true },
    { name: "nsfw_enabled", type: "BOOLEAN", defaultValue: false },
    { name: "api_code", type: "TEXT" },
    { name: "birth_date", type: "DATE" },
    { name: "state", type: "TEXT" },
    { name: "country", type: "TEXT" },
    { name: "phone", type: "TEXT" },
    { name: "pre_registered", type: "BOOLEAN", defaultValue: false },
    { name: "content_creator", type: "BOOLEAN", defaultValue: false },
    { name: "early_access", type: "BOOLEAN", defaultValue: false },
    { name: "profile_photo_url", type: "TEXT" },
    { name: "plan", type: "TEXT" },
    { name: "last_transaction_id", type: "TEXT" },
    { name: "last_transaction_date", type: "DATETIME" },
  ],
  indexes: [
    { name: "idx_profiles_user_id", columns: ["user_id"], unique: true },
    { name: "idx_profiles_username", columns: ["username"], unique: true },
  ],
};

/**
 * Renombra una tabla si existe, para evitar conflictos.
 */
function renameTableIfExists(
  db: Database,
  oldName: string,
  newName: string,
): boolean {
  try {
    db.exec(`ALTER TABLE "${oldName}" RENAME TO "${newName}"`);
    console.log(`   -> Tabla legacy '${oldName}' renombrada a '${newName}'.`);
    return true;
  } catch (e) {
    return false;
  }
}

// En tu archivo scripts/migration.ts, reemplaza la función entera:

/**
 * Migra las asignaciones de roles de usuario de forma robusta.
 * Este es un paso manual porque requiere buscar IDs y mapearlos.
 */
async function migrateUserRoles(db: Database) {
  console.log(
    "🔄 [Paso Adicional] Migrando asignaciones de roles de usuario...",
  );

  // 1. Crear un mapa de los IDs de los roles VIEJOS a sus NOMBRES.
  //    Ej: Map { 1 => 'admin', 2 => 'user' }
  const oldRoles = db
    .query("SELECT idRol, nombreRol FROM roles_legacy")
    .all() as { idRol: number | string; nombreRol: string }[];
  const oldRoleIdToNameMap = new Map(
    oldRoles.map((r) => [r.idRol, r.nombreRol]),
  );

  // 2. Crear un mapa de los NOMBRES de los roles NUEVOS a sus IDs.
  //    Ej: Map { 'admin' => 'xyz...', 'user' => 'abc...' }
  const newRoles = db.query("SELECT id, name FROM roles").all() as {
    id: string;
    name: string;
  }[];
  const newRoleNameToIdMap = new Map(
    newRoles.map((r) => [r.name.toLowerCase(), r.id]),
  );

  // 3. Obtener los usuarios viejos con su ID de usuario y su ID de rol (legacy).
  const oldUsersWithRoles = db
    .query(
      "SELECT idUsuario, rolUsuario FROM usuarios_legacy WHERE rolUsuario IS NOT NULL",
    )
    .all() as { idUsuario: string; rolUsuario: number | string }[];

  if (oldUsersWithRoles.length === 0) {
    console.log("   -> No se encontraron asignaciones de roles para migrar.");
    return;
  }

  const insertStmt = db.prepare(
    "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
  );
  let count = 0;
  let notFoundCount = 0;

  for (const oldUser of oldUsersWithRoles) {
    // 4. Iniciar el mapeo de tres pasos por cada usuario
    // Paso A: Usar el ID de rol viejo para encontrar el NOMBRE del rol.
    const roleName = oldRoleIdToNameMap.get(oldUser.rolUsuario);

    if (roleName) {
      // Paso B: Usar el NOMBRE del rol para encontrar el ID del rol NUEVO.
      const newRoleId = newRoleNameToIdMap.get(roleName.toLowerCase());

      if (newRoleId) {
        // Paso C: Insertar la relación con los IDs nuevos.
        insertStmt.run(oldUser.idUsuario, newRoleId);
        count++;
      } else {
        console.warn(
          `   -> Advertencia: No se encontró el rol '${roleName}' en la nueva tabla de roles (para el usuario ID '${oldUser.idUsuario}').`,
        );
        notFoundCount++;
      }
    } else {
      console.warn(
        `   -> Advertencia: No se encontró un nombre de rol para el ID de rol legacy '${oldUser.rolUsuario}' (para el usuario ID '${oldUser.idUsuario}').`,
      );
      notFoundCount++;
    }
  }

  console.log(`   -> ✅ Se han migrado ${count} asignaciones de roles.`);
  if (notFoundCount > 0) {
    console.log(
      `   -> ⚠️ Hubo ${notFoundCount} asignaciones que no se pudieron migrar por falta de correspondencia.`,
    );
  }
}

/**
 * Función principal y refactorizada para migrar el esquema.
 */
async function main() {
  console.log(
    "🚀 Iniciando el proceso de migración de base de datos (versión completa)...",
  );
  const db = new Database(DATABASE_PATH);

  try {
    // --- PASO PREVIO: AISLAR TABLAS LEGACY ---
    console.log("🔍 [Paso 1/6] Buscando y aislando tablas legacy...");
    const usuariosLegacyExists = renameTableIfExists(
      db,
      "usuarios",
      "usuarios_legacy",
    );
    const rolesLegacyExists = renameTableIfExists(db, "roles", "roles_legacy");

    // --- PASO 2: INICIALIZAR ESQUEMA (LIBRERÍA + EXTENDIDO) ---
    console.log(
      "✅ [Paso 2/6] Inicializando esquema de la librería y tablas personalizadas...",
    );
    const dbInit = new DatabaseInitializer({
      database: db,
      enableWAL: true,
      enableForeignKeys: true,
      // ¡AQUÍ ESTÁ LA CLAVE! Añadimos nuestro esquema personalizado.
      externalSchemas: [userProfileSchema],
    });

    const initResult = await dbInit.initialize();
    if (!initResult.success) {
      throw new Error(
        `Error fatal inicializando el esquema: ${initResult.errors.join(", ")}`,
      );
    }
    console.log(
      `   -> Esquema listo. Tablas creadas: ${initResult.tablesCreated.join(", ")}`,
    );

    // --- PASO 3: SEMBRAR DATOS POR DEFECTO ---
    console.log(
      "🌱 [Paso 3/6] Sembrando datos por defecto (roles, permisos)...",
    );
    await dbInit.seedDefaults();
    console.log("   -> Datos por defecto sembrados.");

    // --- PASO 4: PREPARAR Y EJECUTAR MIGRACIONES DE DATOS ---
    console.log("🔍 [Paso 4/6] Preparando migraciones desde tablas legacy...");
    const migrationsToRun: TableMigration[] = [];

    if (usuariosLegacyExists) {
      // Migración 1: Datos básicos del usuario
      migrationsToRun.push({
        oldTableName: "usuarios_legacy",
        newTableName: "users",
        columnMappings: SPANISH_MAPPINGS.usuarios_a_users,
      });
      console.log("   -> Migración preparada para: usuarios_legacy -> users");

      // Migración 2: Perfil extendido del usuario
      migrationsToRun.push({
        oldTableName: "usuarios_legacy",
        newTableName: "user_profiles",
        columnMappings: SPANISH_MAPPINGS.usuarios_a_profiles,
      });
      console.log(
        "   -> Migración preparada para: usuarios_legacy -> user_profiles",
      );
    }

    if (rolesLegacyExists) {
      migrationsToRun.push({
        oldTableName: "roles_legacy",
        newTableName: "roles",
        columnMappings: SPANISH_MAPPINGS.roles,
      });
      console.log("   -> Migración preparada para: roles_legacy -> roles");
    }

    if (migrationsToRun.length === 0) {
      console.log("🟢 [Paso 4/6] No se encontraron tablas legacy para migrar.");
    } else {
      console.log(`🚀 Ejecutando ${migrationsToRun.length} migraciones...`);
      const migrationManager = new DatabaseMigrationManager({
        database: db,
        migrations: [],
        backupTables: true,
      });
      const migrationResult = await migrationManager.migrate(migrationsToRun);
      if (!migrationResult.success) {
        throw new Error(
          `Fallo en la migración de datos: ${migrationResult.errors.join(", ")}`,
        );
      }
    }

    // --- PASO 5: MIGRAR ASIGNACIONES DE ROLES (CASO ESPECIAL) ---
    if (usuariosLegacyExists) {
      await migrateUserRoles(db);
    }

    // --- PASO 6: MOSTRAR RESULTADOS ---
    console.log("🏁 [Paso 6/6] Proceso de migración completado con éxito.");
  } catch (error: any) {
    console.error(
      "💥 Ha ocurrido un error catastrófico durante la migración:",
      error.message,
    );
  } finally {
    console.log("🚪 Cerrando conexión con la base de datos.");
    db.close();
  }
}

main();
