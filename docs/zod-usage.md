# Using Zod with open-bauth

## Overview

open-bauth now re-exports Zod. This allows users to access all Zod functionalities without needing to install it separately.

## Configuration

### Current Dependency (package.json)
```json
{
  "dependencies": {
    "zod": "^4.1.13"
  }
}
```

### Re-export in src/index.ts
```typescript
// Re-export Zod for user convenience and version control
export * as zod from "zod";
export { z } from "zod";
export type { 
  ZodSchema, 
  ZodType, 
  ZodObject, 
  ZodTypeAny 
} from "zod";
```

## How to Use

### Method 1: Import from open-bauth (Recommended)
```typescript
import { z, BaseController, SchemaExtractor } from "open-bauth";

// Create Zod schemas
const userSchema = z.object({
  id: z.number(),
  name: z.string().min(2),
  email: z.string().email(),
});

// Use with open-bauth controllers
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

### Method 2: Direct Import (Legacy)
```typescript
import { z } from "zod";
import { BaseController } from "open-bauth";

// Same functionality but requires installing Zod separately
```

## Re-export Advantages

### 1. **Single Dependency**
- No need to install Zod separately
- Less configuration in your projects

### 2. **Guaranteed Version Control**
- You'll always use the Zod version compatible with open-bauth
- Avoid version conflicts

### 3. **Cleaner Imports**
```typescript
// Before (2 imports)
import { z } from "zod";
import { BaseController } from "open-bauth";

// After (1 import)
import { z, BaseController } from "open-bauth";
```

### 4. **Optimized Bundle**
- Tree-shaking works better with explicit imports
- No Zod duplication in the bundle

### 5. **Guaranteed Compatibility**
- All open-bauth functions that use Zod work perfectly
- No type or version issues

## Practical Examples

### Schema Extraction with Zod
```typescript
import { z, SchemaExtractor } from "open-bauth";

// Extract database schema and convert to Zod
const extractor = new SchemaExtractor(database);
const schema = await extractor.extractTableSchema('users');

// Validate data using the extracted schema
const userData = { name: 'John', email: 'john@example.com' };
const validatedUser = schema.schema.parse(userData);
```

### Validation in CRUD Operations
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

// Validation is automatic
const result = await controller.create({
  name: 'Laptop',
  price: 999.99,
  category: 'electronics'
});
```

### Advanced Schemas
```typescript
import { z } from "open-bauth";

// Schema with custom validations
const registrationSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});

// Schema with transformations
const userSchema = z.object({
  name: z.string().transform(val => val.trim()),
  email: z.string().email(),
  role: z.enum(['admin', 'user']).default('user'),
});
```

## Build and Publishing

### For Development
During development, examples use direct import:
```typescript
import { z } from "zod"; // Development
```

### For Production
After building the project (`bun run build`), users can use:
```typescript
import { z } from "open-bauth"; // Production
```

### Re-export Verification
```bash
# Verify types
bun run typecheck

# Build project
bun run build

# Test re-export
node -e "console.log(require('./dist/index.js'))"
```

## Bundle Size Impact

### Size Analysis
- **Zod standalone**: ~50KB gzipped
- **With re-export**: ~50KB gzipped (no duplication)
- **Without re-export**: ~50KB + overhead from multiple imports

### Effective Tree-shaking
```typescript
import { z, BaseController } from "open-bauth";
// Only the Zod code you actually use is included
```

## Migration from Direct Import

### Step 1: Update Imports
```typescript
// Before
import { z } from "zod";
import { BaseController } from "open-bauth";

// After
import { z, BaseController } from "open-bauth";
```

### Step 2: Remove Zod from package.json (Optional)
```bash
npm uninstall zod
# or
bun remove zod
```

### Step 3: Verify Functionality
```typescript
import { z } from "open-bauth";

const schema = z.object({
  name: z.string()
});

console.log('Zod works correctly:', schema);
```

## Frequently Asked Questions

### Can I still use Zod directly?
Yes, the old method still works, but the re-export is recommended.

### What if I want a different version of Zod?
The re-export uses the version of Zod we tested with open-bauth. To use another version, import directly.

### Does it work with TypeScript?
Yes, all Zod types are correctly re-exported.

### Will the bundle size be larger?
No, tree-shaking ensures only necessary code is included.

## Summary

The Zod re-export in open-bauth provides:
- Better development experience
- Guaranteed version control
- Optimized bundle
- Full compatibility
- Less configuration
- Cleaner imports

## Automatic Type Mapping

open-bauth uses a centralized utility to map SQL types and JavaScript constructors to Zod validators. This ensures consistency throughout the application.

### Supported Types

| SQL Type / Constructor | Zod Validator | Notes |
|------------------------|---------------|-------|
| `TEXT`, `VARCHAR`, `String` | `z.string()` | |
| `INTEGER`, `INT`, `Number` | `z.number()` | Validated as integer in some contexts |
| `REAL`, `FLOAT` | `z.number()` | |
| `DATE`, `DATETIME`, `Date` | `z.date().or(z.string())` | Accepts Date objects or ISO strings |
| `BLOB`, `BINARY`, `Buffer` | `z.any()` | Flexible for Buffer, Uint8Array, etc. |
| `JSON` | `z.record(z.string(), z.any())` | |

### Flexible Boolean Handling (BIT/BOOLEAN)

To improve compatibility with different database drivers (especially SQLite and SQL Server) and data transmission methods, `BIT` and `BOOLEAN` types use a flexible validator:

```typescript
const flexibleBoolean = z.union([
  z.boolean(),
  z.number(),
  z.instanceof(Uint8Array),
  z.any()
]);
```

This means your boolean fields will accept:
- `true` / `false` (Native booleans)
- `1` / `0` (Integers used by SQLite/MySQL)
- `Uint8Array([1])` / `Buffer.from([0])` (Binary representations)

This is transparent to the end user and avoids common validation errors in complex integrations.

## Cascade Delete Support

Generated schemas and table definitions now support `ON DELETE CASCADE`. This is reflected in the Zod types generated implicitly when handling relationships, ensuring that logical validation matches database behavior.