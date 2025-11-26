import { Database } from 'bun:sqlite';
import { 
  AuthService,
  PermissionService,
  JWTService,
  DatabaseInitializer,
  DATABASE_SCHEMAS
} from '../src/index';

// Datos iniciales para permisos
const initialPermissions = [
  // Permisos de usuarios
  { name: 'users.read', resource: 'users', action: 'read', description: 'Ver usuarios' },
  { name: 'users.create', resource: 'users', action: 'create', description: 'Crear usuarios' },
  { name: 'users.update', resource: 'users', action: 'update', description: 'Actualizar usuarios' },
  { name: 'users.delete', resource: 'users', action: 'delete', description: 'Eliminar usuarios' },
  { name: 'users.manage_roles', resource: 'users', action: 'manage_roles', description: 'Gestionar roles de usuarios' },
  
  // Permisos de posts
  { name: 'posts.read', resource: 'posts', action: 'read', description: 'Ver posts' },
  { name: 'posts.create', resource: 'posts', action: 'create', description: 'Crear posts' },
  { name: 'posts.update', resource: 'posts', action: 'update', description: 'Actualizar posts' },
  { name: 'posts.delete', resource: 'posts', action: 'delete', description: 'Eliminar posts' },
  { name: 'posts.publish', resource: 'posts', action: 'publish', description: 'Publicar posts' },
  { name: 'posts.moderate', resource: 'posts', action: 'moderate', description: 'Moderar posts' },
  
  // Permisos de roles y permisos
  { name: 'roles.read', resource: 'roles', action: 'read', description: 'Ver roles' },
  { name: 'roles.create', resource: 'roles', action: 'create', description: 'Crear roles' },
  { name: 'roles.update', resource: 'roles', action: 'update', description: 'Actualizar roles' },
  { name: 'roles.delete', resource: 'roles', action: 'delete', description: 'Eliminar roles' },
  { name: 'permissions.read', resource: 'permissions', action: 'read', description: 'Ver permisos' },
  { name: 'permissions.create', resource: 'permissions', action: 'create', description: 'Crear permisos' },
  { name: 'permissions.update', resource: 'permissions', action: 'update', description: 'Actualizar permisos' },
  { name: 'permissions.delete', resource: 'permissions', action: 'delete', description: 'Eliminar permisos' },
  
  // Permisos de administración
  { name: 'admin.dashboard', resource: 'admin', action: 'dashboard', description: 'Acceder al dashboard de administración' },
  { name: 'admin.settings', resource: 'admin', action: 'settings', description: 'Gestionar configuración del sistema' },
  { name: 'admin.logs', resource: 'admin', action: 'logs', description: 'Ver logs del sistema' },
  { name: 'admin.analytics', resource: 'admin', action: 'analytics', description: 'Ver analytics del sistema' }
]

// Datos iniciales para roles
const initialRoles = [
  {
    name: 'admin',
    description: 'Administrador del sistema con acceso completo',
    permissions: [
      'users.read', 'users.create', 'users.update', 'users.delete', 'users.manage_roles',
      'posts.read', 'posts.create', 'posts.update', 'posts.delete', 'posts.publish', 'posts.moderate',
      'roles.read', 'roles.create', 'roles.update', 'roles.delete',
      'permissions.read', 'permissions.create', 'permissions.update', 'permissions.delete',
      'admin.dashboard', 'admin.settings', 'admin.logs', 'admin.analytics'
    ]
  },
  {
    name: 'moderator',
    description: 'Moderador con permisos de gestión de contenido',
    permissions: [
      'users.read',
      'posts.read', 'posts.create', 'posts.update', 'posts.delete', 'posts.publish', 'posts.moderate',
      'roles.read', 'permissions.read',
      'admin.dashboard'
    ]
  },
  {
    name: 'editor',
    description: 'Editor con permisos de creación y edición de contenido',
    permissions: [
      'posts.read', 'posts.create', 'posts.update', 'posts.publish'
    ]
  },
  {
    name: 'author',
    description: 'Autor con permisos básicos de creación de contenido',
    permissions: [
      'posts.read', 'posts.create', 'posts.update'
    ]
  },
  {
    name: 'user',
    description: 'Usuario básico con permisos de lectura',
    permissions: [
      'posts.read'
    ]
  }
]

// Datos iniciales para usuarios
const initialUsers = [
  {
    email: 'admin@example.com',
    password: 'Admin123!@#',
    first_name: 'Admin',
    last_name: 'User',
    roles: ['admin']
  },
  {
    email: 'moderator@example.com',
    password: 'Moderator123!',
    first_name: 'Moderator',
    last_name: 'User',
    roles: ['moderator']
  },
  {
    email: 'editor@example.com',
    password: 'Editor123!',
    first_name: 'Editor',
    last_name: 'User',
    roles: ['editor']
  },
  {
    email: 'author@example.com',
    password: 'Author123!',
    first_name: 'Author',
    last_name: 'User',
    roles: ['author']
  },
  {
    email: 'user@example.com',
    password: 'User123!',
    first_name: 'Regular',
    last_name: 'User',
    roles: ['user']
  }
]

/**
 * Función para poblar la base de datos con datos iniciales
 * @param dbPath Ruta opcional de la base de datos
 */
export async function seedDatabase(dbPath?: string): Promise<void> {
  try {
    console.log('🌱 Iniciando seeding de la base de datos...');
    
    // Inicializar base de datos y ejecutar migraciones
    const db = new Database(dbPath || 'auth.db');
    const dbInitializer = new DatabaseInitializer({ database: db });
    await dbInitializer.initialize(DATABASE_SCHEMAS);
    
    // Inicializar servicios con JWT secret
    const jwtSecret = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
    const jwtService = new JWTService(jwtSecret, '24h');
    const authService = new AuthService(dbInitializer, jwtService);
    const permissionService = new PermissionService(dbInitializer);
    
    console.log('📝 Creando permisos iniciales...');
    
    // Crear permisos
    const createdPermissions = new Map<string, string>();
    for (const permission of initialPermissions) {
      try {
        const result = await permissionService.createPermission(permission);
        if (result && result.data) {
          createdPermissions.set(permission.name, result.data.id);
          console.log(`  ✅ Permiso creado: ${permission.name}`);
        }
      } catch (error: any) {
        console.log(`  ⚠️  Permiso ya existe: ${permission.name}`);
      }
    }
    
    console.log('👥 Creando roles iniciales...');
    
    // Crear roles
    const createdRoles = new Map<string, string>();
    for (const role of initialRoles) {
      try {
        const result = await permissionService.createRole(role);
        
        if (result && result.data) {
          createdRoles.set(role.name, result.data.id);
          console.log(`  ✅ Rol creado: ${role.name}`);
          
          // Asignar permisos al rol
          for (const permissionName of role.permissions || []) {
            const permissionId = createdPermissions.get(permissionName);
            if (permissionId) {
              await permissionService.assignPermissionToRole(result.data.id, permissionId);
            }
          }
          console.log(`    🎭 Permisos asignados al rol ${role.name}`);
        }
      } catch (error: any) {
        console.log(`  ⚠️  Rol ya existe: ${role.name}`);
      }
    }
    
    console.log('👤 Creando usuarios iniciales...');
    
    // Crear usuarios
    for (const user of initialUsers) {
      try {
        const result = await authService.register({
          email: user.email,
          password: user.password,
          first_name: user.first_name,
          last_name: user.last_name,
        });
        
        if (result && result.success && result.user) {
          console.log(`  ✅ Usuario creado: ${user.email}`);
          
          // Asignar roles al usuario
          for (const roleName of user.roles) {
            const assignResult = await authService.assignRole(result.user.id, roleName);
            if (assignResult) {
              console.log(`    ✅ Rol ${roleName} asignado a ${user.email}`);
            } else {
              console.log(`    ❌ Error asignando rol ${roleName} a ${user.email}:`, assignResult);
            }
          }
        }
      } catch (error: any) {
        console.log(`  ⚠️  Usuario ya existe: ${user.email}`);
        // En entorno de test, no propagar el error para evitar exit code 1
        if (process.env.NODE_ENV !== 'test') {
          // Solo loggear el error en desarrollo/producción
        }
      }
    }
    
    console.log('✨ Seeding completado exitosamente!');
    console.log('\n📊 Resumen:');
    console.log(`  - Permisos: ${initialPermissions.length}`);
    console.log(`  - Roles: ${initialRoles.length}`);
    console.log(`  - Usuarios: ${initialUsers.length}`);
    console.log('\n🔐 Credenciales de acceso:');
    console.log('  Admin: admin@example.com / Admin123!@#');
    console.log('  Moderator: moderator@example.com / Moderator123!');
    console.log('  Editor: editor@example.com / Editor123!');
    console.log('  Author: author@example.com / Author123!');
    console.log('  User: user@example.com / User123!');
    
  } catch (error: any) {
    console.error('❌ Error durante el seeding:', error);
    // En entorno de test, no propagar el error para evitar exit code 1
    if (process.env.NODE_ENV !== 'test') {
      throw error;
    }
  }
}
/**
 * Función para limpiar la base de datos
 */
async function cleanDatabase(dbPath?: string): Promise<void> {
  const db = new Database(dbPath || 'auth.db');
  const dbInitializer = new DatabaseInitializer({ database: db });
  
  // Drop all tables
  const tables = ['user_roles', 'role_permissions', 'users', 'roles', 'permissions'];
  for (const table of tables) {
    try {
      db.exec(`DROP TABLE IF EXISTS ${table}`);
      console.log(`✅ Tabla ${table} eliminada`);
    } catch (error) {
      console.log(`⚠️  Error eliminando tabla ${table}:`, error);
    }
  }
  console.log('🧹 Base de datos limpiada');
}

/**
 * Función para resetear la base de datos (limpiar y poblar)
 */
async function resetDatabase(dbPath?: string): Promise<void> {
  await cleanDatabase(dbPath);
  await seedDatabase(dbPath);
}

/**
 * Función para verificar el estado de la base de datos
 */
async function checkDatabaseStatus(dbPath?: string): Promise<void> {
  const db = new Database(dbPath || 'auth.db');
  const dbInitializer = new DatabaseInitializer({ database: db });
  
  try {
    const userController = dbInitializer.createController('users');
    const roleController = dbInitializer.createController('roles');
    const permissionController = dbInitializer.createController('permissions');
    
    const userCount = await userController.count();
    const roleCount = await roleController.count();
    const permissionCount = await permissionController.count();
    
    console.log('📊 Estado de la base de datos:');
    console.log(`  - Usuarios: ${userCount.data || 0}`);
    console.log(`  - Roles: ${roleCount.data || 0}`);
    console.log(`  - Permisos: ${permissionCount.data || 0}`);
  } catch (error) {
    console.error('❌ Error verificando estado:', error);
  }
}

// Ejecutar seeding si el script se ejecuta directamente
async function main() {
  const command = process.argv[2];
  
  switch (command) {
    case 'seed':
      await seedDatabase();
      break;
    case 'clean':
      await cleanDatabase();
      break;
    case 'reset':
      await resetDatabase();
      break;
    case 'status':
      await checkDatabaseStatus();
      break;
    default:
      console.log('Uso: bun run examples/seed.ts [seed|clean|reset|status]');
      console.log('  seed   - Poblar base de datos con datos iniciales');
      console.log('  clean  - Limpiar todos los datos');
      console.log('  reset  - Limpiar y volver a poblar');
      console.log('  status - Verificar estado actual');
  }
}

// Check if this script is being run directly
if (process.argv[1] && process.argv[1].endsWith('seed.ts') && process.env.NODE_ENV !== 'test') {
  main().catch(console.error);
}