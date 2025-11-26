/**
 * Sistema de errores estandarizado para operaciones de base de datos
 * Proporciona categorización y contexto consistente para todos los errores
 */

export enum DatabaseErrorType {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  NOT_FOUND = 'NOT_FOUND',
  CONSTRAINT_VIOLATION = 'CONSTRAINT_VIOLATION',
  CONNECTION_ERROR = 'CONNECTION_ERROR',
  QUERY_ERROR = 'QUERY_ERROR',
  TRANSACTION_ERROR = 'TRANSACTION_ERROR',
  INITIALIZATION_ERROR = 'INITIALIZATION_ERROR',
  MIGRATION_ERROR = 'MIGRATION_ERROR',
  UNKNOWN_ERROR = 'UNKNOWN_ERROR'
}

export interface DatabaseError {
  type: DatabaseErrorType;
  message: string;
  originalError?: unknown;
  details?: Record<string, unknown>;
  timestamp?: string;
}

export interface ControllerError<T = any> {
  success: false;
  error: string;
  errorType: DatabaseErrorType;
  details?: Record<string, unknown>;
  originalError?: unknown;
}

export interface ControllerResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  errorType?: DatabaseErrorType;
  message?: string;
  total?: number;
}

/**
 * Función helper para categorizar errores de base de datos
 */
export function categorizeError(error: unknown): DatabaseError {
  const timestamp = new Date().toISOString();
  
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    
    // Constraint violations
    if (message.includes('unique constraint') || 
        message.includes('duplicate key') || 
        message.includes('duplicate entry')) {
      return {
        type: DatabaseErrorType.CONSTRAINT_VIOLATION,
        message: 'Record already exists or violates unique constraint',
        originalError: error,
        timestamp
      };
    }
    
    // Foreign key constraints
    if (message.includes('foreign key constraint') || 
        message.includes('foreign key violation')) {
      return {
        type: DatabaseErrorType.CONSTRAINT_VIOLATION,
        message: 'Foreign key constraint violation',
        originalError: error,
        timestamp
      };
    }
    
    // Not null constraints
    if (message.includes('not null constraint') || 
        message.includes('cannot be null')) {
      return {
        type: DatabaseErrorType.VALIDATION_ERROR,
        message: 'Required field is missing or null',
        originalError: error,
        timestamp
      };
    }
    
    // Table/column errors
    if (message.includes('no such table') || 
        message.includes('table') && message.includes('doesn\'t exist') ||
        message.includes('column') && message.includes('does not exist')) {
      return {
        type: DatabaseErrorType.QUERY_ERROR,
        message: 'Table or column does not exist',
        originalError: error,
        timestamp
      };
    }
    
    // Connection errors
    if (message.includes('connection') || 
        message.includes('database is locked') ||
        message.includes('unable to open database') ||
        message.includes('connection refused')) {
      return {
        type: DatabaseErrorType.CONNECTION_ERROR,
        message: 'Database connection error',
        originalError: error,
        timestamp
      };
    }
    
    // Syntax errors
    if (message.includes('syntax error') || 
        message.includes('sql syntax') ||
        message.includes('near') && message.includes('syntax')) {
      return {
        type: DatabaseErrorType.QUERY_ERROR,
        message: 'SQL syntax error',
        originalError: error,
        timestamp
      };
    }
  }
  
  // Fallback para errores desconocidos
  return {
    type: DatabaseErrorType.UNKNOWN_ERROR,
    message: error instanceof Error ? error.message : 'Unknown error occurred',
    originalError: error,
    timestamp
  };
}

/**
 * Crea una respuesta de error estandarizada para el controlador
 */
export function createErrorResponse<T = any>(
  error: unknown,
  additionalDetails?: Record<string, unknown>
): ControllerError<T> {
  const dbError = categorizeError(error);
  
  return {
    success: false,
    error: dbError.message,
    errorType: dbError.type,
    details: {
      ...dbError.details,
      ...additionalDetails,
      timestamp: dbError.timestamp
    },
    originalError: dbError.originalError
  };
}

/**
 * Verifica si un error es recuperable (puede reintentarse)
 */
export function isRecoverableError(errorType: DatabaseErrorType): boolean {
  const recoverableTypes = [
    DatabaseErrorType.CONNECTION_ERROR,
    DatabaseErrorType.TRANSACTION_ERROR
  ];
  
  return recoverableTypes.includes(errorType);
}

/**
 * Verifica si un error es de validación (error del cliente)
 */
export function isValidationError(errorType: DatabaseErrorType): boolean {
  return errorType === DatabaseErrorType.VALIDATION_ERROR;
}

/**
 * Verifica si un error es de constraints (datos incorrectos)
 */
export function isConstraintError(errorType: DatabaseErrorType): boolean {
  return errorType === DatabaseErrorType.CONSTRAINT_VIOLATION;
}
