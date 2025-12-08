import { z } from "zod";

export type ConstructorType =
    | StringConstructor
    | NumberConstructor
    | BooleanConstructor
    | DateConstructor
    | ObjectConstructor
    | ArrayConstructor
    | BufferConstructor;

// Custom helper for flexible boolean (accepts true/false, 0/1, Uint8Array/Buffer)
export const flexibleBoolean = z.union([
    z.boolean(),
    z.number(),
    z.instanceof(Uint8Array),
    z.any() // Safety net for Buffer or other weird objects, though Uint8Array covers Buffer usually
]);

export const mapSqlTypeToZodType = (type: string): z.ZodTypeAny => {
    const upperType = type.toUpperCase();
    const baseType = upperType.split("(")[0]?.trim() || upperType.trim();

    switch (baseType) {
        case "INTEGER":
        case "INT":
        case "BIGINT":
        case "SMALLINT":
        case "TINYINT":
        case "SERIAL":
            return z.number();

        case "REAL":
        case "FLOAT":
        case "DOUBLE":
        case "NUMERIC":
        case "DECIMAL":
            return z.number();

        case "TEXT":
        case "VARCHAR":
        case "CHAR":
        case "CLOB":
        case "NVARCHAR":
        case "NCHAR":
            return z.string();

        case "BOOLEAN":
        case "BIT":
            return flexibleBoolean;

        case "DATE":
        case "DATETIME":
        case "TIMESTAMP":
            // Unified strategy: Allow Date objects or valid strings
            return z.date().or(z.string());

        case "BLOB":
        case "BINARY":
            // Unified strategy: Accept any for Buffer/Blob
            return z.any();

        case "JSON":
            return z.record(z.string(), z.any());

        default:
            return z.string();
    }
};

export const mapConstructorToZodType = (type: ConstructorType | any): z.ZodTypeAny => {
    switch (type) {
        case String: return z.string();
        case Number: return z.number();
        case Boolean: return flexibleBoolean;
        case Date: return z.date().or(z.string().datetime()).or(z.string());
        case Object: return z.record(z.string(), z.any());
        case Array: return z.array(z.any());
        case Buffer: return z.any();
        default: return z.any();
    }
};
