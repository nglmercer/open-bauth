# Uso de Zod con open-bauth

## Overview

open-bauth ahora reexporta Zod. Esto permite a los usuarios acceder a todas las funcionalidades de Zod sin necesidad de instalarlo por separado.

## Configuración

### Dependencia actual (package.json)
```json
{
  "dependencies": {
    "zod": "^4.1.13"
  }
}
```

### Reexport en src/index.ts
```typescript
// Reexportar Zod para conveniencia de usuarios y control de versiones
export * as zod from "zod";
export { z } from "zod";
export type { 
  ZodSchema, 
  ZodType, 
  ZodObject, 
  ZodTypeAny 
} from "zod";
```

## Cómo Usar

### Método 1: Importación desde open-bauth (Recomendado)
```typescript
import { z, BaseController, SchemaExtractor } from "open-bauth";

// Crear schemas Zod
const userSchema = z.object({
  id: z.number(),
  name: z.string().min(2),
  email: z.string().email(),
});

// Usar con controladores de open-bauth
const controller = new BaseController('users', {
  database: db,
  schemas: {
    users: {
      create: userSchema,
      update: userSchema.partial(),
      read: userSchema,
    }
  }
});
```

### Método 2: Importación directa (Legacy)
```typescript
import { z } from "zod";
import { BaseController } from "open-bauth";

// Mismo funcionamiento pero requiere instalar Zod por separado
```

## Ventajas del Reexport

### 1. **Una sola dependencia**
- No necesitas instalar Zod por separado
- Menos configuración en tus proyectos

### 2. **Control de versiones garantizado**
- Siempre usarás la versión de Zod compatible con open-bauth
- Evitas conflictos entre versiones

### 3. **Imports más limpios**
```typescript
// Antes (2 imports)
import { z } from "zod";
import { BaseController } from "open-bauth";

// Después (1 import)
import { z, BaseController } from "open-bauth";
```

### 4. **Bundle optimizado**
- Tree-shaking funciona mejor con imports explícitos
- No hay duplicación de Zod en el bundle

### 5. **Compatibilidad garantizada**
- Todas las funciones de open-bauth que usan Zod funcionan perfectamente
- Sin problemas de tipos o versiones

## Ejemplos Prácticos

### Schema Extraction con Zod
```typescript
import { z, SchemaExtractor } from "open-bauth";

// Extraer esquema de base de datos y convertir a Zod
const extractor = new SchemaExtractor(database);
const schema = await extractor.extractTableSchema('users');

// Validar datos usando el schema extraído
const userData = { name: 'John', email: 'john@example.com' };
const validatedUser = schema.schema.parse(userData);
```

### Validación en CRUD Operations
```typescript
import { z, BaseController } from "open-bauth";

const productSchema = z.object({
  name: z.string().min(1),
  price: z.number().positive(),
  category: z.enum(['electronics', 'clothing']),
});

const controller = new BaseController('products', {
  database: db,
  schemas: {
    products: {
      create: productSchema,
      update: productSchema.partial(),
    }
  }
});

// La validación es automática
const result = await controller.create({
  name: 'Laptop',
  price: 999.99,
  category: 'electronics'
});
```

### Schemas Avanzados
```typescript
import { z } from "open-bauth";

// Schema con validaciones personalizadas
const registrationSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Las contraseñas no coinciden",
  path: ["confirmPassword"],
});

// Schema con transformaciones
const userSchema = z.object({
  name: z.string().transform(val => val.trim()),
  email: z.string().email(),
  role: z.enum(['admin', 'user']).default('user'),
});
```

## Construcción y Publicación

### Para el desarrollo
Durante el desarrollo, los ejemplos usan el import directo:
```typescript
import { z } from "zod"; // Desarrollo
```

### Para producción
Después de construir el proyecto (`bun run build`), los usuarios pueden usar:
```typescript
import { z } from "open-bauth"; // Producción
```

### Verificación del reexport
```bash
# Verificar tipos
bun run typecheck

# Construir proyecto
bun run build

# Probar reexport
node -e "console.log(require('./dist/index.js'))"
```

## Impacto en el Bundle Size

### Análisis de tamaño
- **Zod standalone**: ~50KB gzipped
- **Con reexport**: ~50KB gzipped (sin duplicación)
- **Sin reexport**: ~50KB + overhead de múltiples imports

### Tree-shaking efectivo
```typescript
import { z, BaseController } from "open-bauth";
// Solo se incluye el código de Zod que realmente usas
```

## Migración desde import directo

### Paso 1: Actualizar imports
```typescript
// Antes
import { z } from "zod";
import { BaseController } from "open-bauth";

// Después
import { z, BaseController } from "open-bauth";
```

### Paso 2: Remover Zod de package.json (opcional)
```bash
npm uninstall zod
# o
bun remove zod
```

### Paso 3: Verificar funcionamiento
```typescript
import { z } from "open-bauth";

const schema = z.object({
  name: z.string()
});

console.log('Zod funciona correctamente:', schema);
```

## Preguntas Frecuentes

### ¿Puedo seguir usando Zod directamente?
Sí, el método antiguo sigue funcionando, pero el reexport es recomendado.

### ¿Qué pasa si quiero una versión diferente de Zod?
El reexport usa la versión de Zod que probamos con open-bauth. Para usar otra versión, importa directamente.

### ¿Funciona con TypeScript?
Sí, todos los tipos de Zod están reexportados correctamente.

### ¿El bundle size será mayor?
No, el tree-shaking asegura que solo se incluya el código necesario.

## Resumen

El reexport de Zod en open-bauth proporciona:
- ✅ Mejor experiencia de desarrollo
- ✅ Control de versiones garantizado
- ✅ Bundle optimizado
- ✅ Compatibilidad total
- ✅ Menos configuración
- ✅ imports más limpios


## Mapeo Automático de Tipos

open-bauth utiliza una utilidad centralizada para mapear tipos de SQL y constructores de JavaScript a validadores Zod. Esto asegura consistencia en toda la aplicación.

### Tipos Soportados

| SQL Type / Constructor | Zod Validator | Notas |
|------------------------|---------------|-------|
| `TEXT`, `VARCHAR`, `String` | `z.string()` | |
| `INTEGER`, `INT`, `Number` | `z.number()` | Validado como entero en algunos contextos |
| `REAL`, `FLOAT` | `z.number()` | |
| `DATE`, `DATETIME`, `Date` | `z.date().or(z.string())` | Acepta objetos Date o strings ISO |
| `BLOB`, `BINARY`, `Buffer` | `z.any()` | Flexible para Buffer, Uint8Array, etc. |
| `JSON` | `z.record(z.string(), z.any())` | |

### Manejo Flexible de Booleanos (BIT/BOOLEAN)

Para mejorar la compatibilidad con diferentes drivers de base de datos (especialmente SQLite y SQL Server) y formas de transmisión de datos, los tipos `BIT` y `BOOLEAN` utilizan un validador flexible:

```typescript
const flexibleBoolean = z.union([
  z.boolean(),
  z.number(),
  z.instanceof(Uint8Array),
  z.any()
]);
```

Esto significa que tus campos booleanos aceptarán:
- `true` / `false` (Booleans nativos)
- `1` / `0` (Enteros usados por SQLite/MySQL)
- `Uint8Array([1])` / `Buffer.from([0])` (Representaciones binarias)

Esto es transparente para el usuario final y evita errores de validación comunes en integraciones complejas.

## Soporte para Cascade Delete

Los esquemas generados y las definiciones de tabla ahora soportan `ON DELETE CASCADE`. Esto se refleja en los tipos Zod generados implícitamente al manejar relaciones, asegurando que la validación lógica coincida con el comportamiento de la base de datos.

