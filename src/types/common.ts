import { Database } from "bun:sqlite";
/**
 * Common utility types and interfaces
 */

/**
 * Generic API response wrapper
 */
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  meta?: {
    timestamp: string;
    requestId?: string;
    version?: string;
  };
}

/**
 * Paginated response interface
 */
export interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

/**
 * Database entity base interface
 */
export interface BaseEntity {
  id: string;
  created_at?: string;
  updated_at?: string;
}

/**
 * Soft delete entity interface
 */
export interface SoftDeleteEntity extends BaseEntity {
  deletedAt?: string;
  isDeleted: boolean;
}

/**
 * Audit fields interface
 */
export interface AuditFields {
  createdBy?: string;
  updatedBy?: string;
  deletedBy?: string;
}

/**
 * Query options interface
 */
export interface QueryOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
  search?: string;
  filters?: Record<string, unknown>;
}

/**
 * Database transaction interface
 */
export interface DatabaseTransaction {
  commit(): Promise<void>;
  rollback(): Promise<void>;
  is_active(): boolean;
  getDatabase(): Database;
}

/**
 * Repository interface
 */
export interface Repository<
  T extends BaseEntity,
  CreateData = Partial<T>,
  UpdateData = Partial<T>,
> {
  findById(id: string, options?: QueryOptions): Promise<T | null>;
  findMany(options?: QueryOptions): Promise<PaginatedResponse<T>>;
  create(data: CreateData, transaction?: DatabaseTransaction): Promise<T>;
  update(
    id: string,
    data: UpdateData,
    transaction?: DatabaseTransaction,
  ): Promise<T>;
  delete(id: string, transaction?: DatabaseTransaction): Promise<boolean>;
  exists(id: string): Promise<boolean>;
}

/**
 * Service interface
 */
export interface Service<T, CreateData = Partial<T>, UpdateData = Partial<T>> {
  findById(id: string): Promise<T | null>;
  create(data: CreateData): Promise<T>;
  update(id: string, data: UpdateData): Promise<T>;
  delete(id: string): Promise<boolean>;
}

/**
 * Validation result interface
 */
export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  warnings?: ValidationWarning[];
}

/**
 * Validation error interface
 */
export interface ValidationError {
  field: string;
  message: string;
  code: string;
  value?: unknown;
}

/**
 * Validation warning interface
 */
export interface ValidationWarning {
  field: string;
  message: string;
  code: string;
  value?: unknown;
}

/**
 * Configuration interface
 */
export interface Configuration {
  database: DatabaseConfig;
  auth: AuthConfig;
  security: SecurityConfig;
  logging: LoggingConfig;
}

/**
 * Database configuration interface
 */
export interface DatabaseConfig {
  type: "sqlite" | "mysql" | "postgresql";
  host?: string;
  port?: number;
  database: string;
  username?: string;
  password?: string;
  ssl?: boolean;
  pool?: {
    min: number;
    max: number;
    idle: number;
  };
}

/**
 * Auth configuration interface
 */
export interface AuthConfig {
  jwt: {
    secret: string;
    expiresIn: string;
    refreshExpiresIn: string;
    algorithm: string;
    issuer: string;
    audience: string;
  };
  password: {
    minLength: number;
    maxLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
    saltRounds: number;
  };
  session: {
    timeout: number;
    maxLoginAttempts: number;
    lockoutDuration: number;
  };
}

/**
 * Security configuration interface
 */
export interface SecurityConfig {
  rateLimiting: {
    enabled: boolean;
    windowMs: number;
    maxRequests: number;
  };
  cors: {
    enabled: boolean;
    origin: string | string[];
    credentials: boolean;
  };
  helmet: {
    enabled: boolean;
    options: Record<string, unknown>;
  };
}

/**
 * Logging configuration interface
 */
export interface LoggingConfig {
  level: "debug" | "info" | "warn" | "error";
  format: "json" | "text";
  outputs: ("console" | "file" | "database")[];
  audit: {
    enabled: boolean;
    logSuccessfulRequests: boolean;
    logFailedRequests: boolean;
  };
}

/**
 * HTTP status codes enum
 */
export enum HttpStatusCode {
  OK = 200,
  CREATED = 201,
  NO_CONTENT = 204,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  CONFLICT = 409,
  UNPROCESSABLE_ENTITY = 422,
  TOO_MANY_REQUESTS = 429,
  INTERNAL_SERVER_ERROR = 500,
  SERVICE_UNAVAILABLE = 503,
}

/**
 * Environment types
 */
export type Environment = "development" | "test" | "staging" | "production";

/**
 * Utility types
 */
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequiredFields<T, K extends keyof T> = T & { [P in K]-?: T[P] };
export type Nullable<T> = T | null;
export type Maybe<T> = T | undefined;
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
export type DeepRequired<T> = {
  [P in keyof T]-?: T[P] extends object ? DeepRequired<T[P]> : T[P];
};

/**
 * Function types
 */
export type AsyncFunction<T = void> = () => Promise<T>;
export type Callback<T = void> = (error?: Error, result?: T) => void;
export type EventHandler<T = unknown> = (event: T) => void | Promise<void>;

/**
 * Date utility types
 */
export type DateString = string; // ISO 8601 date string
export type Timestamp = number; // Unix timestamp

/**
 * ID types
 */
export type EntityId = string;
export type UserId = string;
export type RoleId = string;
export type PermissionId = string;

/**
 * Brand types for better type safety
 */
export type Brand<T, B> = T & { __brand: B };
export type Email = Brand<string, "Email"> | string;
export type HashedPassword = Brand<string, "HashedPassword"> | string;
export type JWT = Brand<string, "JWT"> | string;
export type RefreshToken = Brand<string, "RefreshToken">;

/**
 * Result type for error handling
 */
export type Result<T, E = Error> =
  | { success: true; data: T }
  | { success: false; error: E };

/**
 * Option type
 */
export type Option<T> = T | null | undefined;

/**
 * Event types
 */
export interface DomainEvent {
  id: string;
  type: string;
  aggregateId: string;
  aggregateType: string;
  version: number;
  timestamp: string;
  data: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/**
 * Command types
 */
export interface Command {
  id: string;
  type: string;
  timestamp: string;
  userId?: string;
  data: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/**
 * Query types
 */
export interface Query {
  id: string;
  type: string;
  timestamp: string;
  userId?: string;
  parameters: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}
