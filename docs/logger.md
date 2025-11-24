# Logger Documentation

The library includes a production-ready, flexible logging system built on [`EventEmitter`](node:events) with support for console/file output, rotation, JSON/text formats, colors, and configurable levels.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Log Levels](#log-levels)
- [Configuration](#configuration)
- [Logger Class](#logger-class)
- [Convenience Functions](#convenience-functions)
- [File Management](#file-management)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)

## 🌟 Overview

### Key Features

- **Multiple Log Levels**: DEBUG, INFO, WARN, ERROR, FATAL, SILENT
- **Flexible Outputs**: Console with colors, file with rotation
- **Format Options**: Structured JSON or human-readable text
- **Singleton Pattern**: Global logger instance with `getLogger()`
- **Event-Driven**: Built on EventEmitter for extensibility
- **Environment-Based**: Pre-configured setups for dev/prod/test
- **Performance Optimized**: Efficient logging with minimal overhead

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                      │
└─────────────────────┬───────────────────────────────────┘
                      │ Logger Interface
┌─────────────────────▼───────────────────────────────────┐
│              Logger Class                                │
│  ┌─────────────┬─────────────┐                      │
│  │   Console   │    File     │                      │
│  │   Output    │    Output   │                      │
│  └─────────────┴─────────────┘                      │
│  ┌─────────────┬─────────────┐                      │
│  │   JSON      │    Text     │                      │
│  │  Formatter  │  Formatter  │                      │
│  └─────────────┴─────────────┘                      │
│  ┌─────────────┬─────────────┐                      │
│  │   Colors    │   Rotation  │                      │
│  └─────────────┴─────────────┘                      │
└─────────────────────┬───────────────────────────────────┘
                      │ EventEmitter
┌─────────────────────▼───────────────────────────────────┐
│              Event System                               │
│  - 'log' events with LogEntry data                 │
│  - 'error' events for error handling               │
│  - 'rotate' events for file rotation              │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Basic Usage

```typescript
import { getLogger, log, LogLevel } from 'open-bauth/src/logger';

// Get logger with default configuration
const logger = getLogger();

// Use convenience functions
log.info('user.login', { userId: '123', ip: '192.168.1.1' });
log.error('database.error', { error: 'Connection failed', table: 'users' });
log.debug('api.request', { method: 'GET', url: '/api/users' });
```

### Custom Configuration

```typescript
import { getLogger, LogLevel } from 'open-bauth/src/logger';

const logger = getLogger({
  level: LogLevel.INFO,
  enableFile: true,
  logDirectory: './logs',
  maxFileSize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5,
  format: 'json',
  includeStackTrace: true,
  colors: {
    info: 'blue',
    warn: 'yellow',
    error: 'red'
  }
});
```

## 📊 Log Levels

### Level Hierarchy

```typescript
enum LogLevel {
  DEBUG = 0,    // Detailed debugging information
  INFO = 1,     // General information messages
  WARN = 2,     // Warning messages for potential issues
  ERROR = 3,    // Error messages for failures
  FATAL = 4,    // Critical errors causing termination
  SILENT = 5    // No logging output
}
```

### Level Filtering

Only messages at or above the configured level are logged:

```typescript
// With LogLevel.INFO (1):
log.debug('debug.message'); // Not logged (0 < 1)
log.info('info.message');   // Logged (1 >= 1)
log.warn('warn.message');   // Logged (2 >= 1)
log.error('error.message'); // Logged (3 >= 1)
```

## ⚙️ Configuration

### Environment-Based Configuration

Pre-configured setups available via [`createConfig`](src/logger/config.ts:47):

```typescript
import { createConfig, ENVIRONMENT_CONFIGS } from 'open-bauth/src/logger';

// Development configuration
const devConfig = ENVIRONMENT_CONFIGS.development;
// {
//   level: LogLevel.DEBUG,
//   enableFile: true,
//   format: 'text',
//   colors: true,
//   includeStackTrace: true
// }

// Production configuration
const prodConfig = ENVIRONMENT_CONFIGS.production;
// {
//   level: LogLevel.INFO,
//   enableFile: true,
//   format: 'json',
//   colors: false,
//   includeStackTrace: false
// }

// Test configuration
const testConfig = ENVIRONMENT_CONFIGS.test;
// {
//   level: LogLevel.SILENT,
//   enableFile: false,
//   format: 'json',
//   colors: false,
//   includeStackTrace: false
// }
```

### LoggerConfig Interface

```typescript
interface LoggerConfig {
  // Core settings
  level: LogLevel;
  enableConsole: boolean;
  enableFile: boolean;
  
  // File settings
  logDirectory?: string;
  maxFileSize?: number;
  maxFiles?: number;
  datePattern?: string;
  
  // Format settings
  format: 'json' | 'text';
  includeTimestamp: boolean;
  includeStackTrace: boolean;
  
  // Visual settings
  colors: boolean | Record<LogLevel, string>;
  
  // Advanced settings
  enableEvents: boolean;
  bufferMaxSize?: number;
  flushInterval?: number;
}
```

### Configuration Examples

```typescript
// Development with colorful console output
const devLogger = getLogger({
  level: LogLevel.DEBUG,
  enableConsole: true,
  enableFile: true,
  format: 'text',
  colors: {
    debug: 'gray',
    info: 'blue',
    warn: 'yellow',
    error: 'red',
    fatal: 'magenta'
  },
  includeStackTrace: true
});

// Production with JSON file output
const prodLogger = getLogger({
  level: LogLevel.INFO,
  enableConsole: false,
  enableFile: true,
  logDirectory: './logs',
  maxFileSize: 50 * 1024 * 1024, // 50MB
  maxFiles: 10,
  format: 'json',
  colors: false,
  includeStackTrace: false
});

// High-performance with buffering
const perfLogger = getLogger({
  level: LogLevel.WARN,
  enableEvents: true,
  bufferMaxSize: 1000,
  flushInterval: 5000 // 5 seconds
});
```

## 📝 Logger Class

### [`Logger`](src/logger/Logger.ts:9)

Main logging class with comprehensive functionality.

#### Logging Methods

- [`debug(event, data?, ...args)`](src/logger/Logger.ts:82)
- [`info(event, data?, ...args)`](src/logger/Logger.ts:86)
- [`warn(event, data?, ...args)`](src/logger/Logger.ts:90)
- [`error(event, data?, ...args)`](src/logger/Logger.ts:94)
- [`fatal(event, data?, ...args)`](src/logger/Logger.ts:98)

#### Configuration Methods

- [`updateConfig(config)`](src/logger/Logger.ts:103) - Update configuration at runtime
- [`getConfig()`](src/logger/Logger.ts:109) - Get current configuration
- [`silence()`](src/logger/Logger.ts:114) - Disable all logging
- [`unsilence(level?)`](src/logger/Logger.ts:118) - Re-enable logging with optional level
- [`enableConsoleOnly()`](src/logger/Logger.ts:122) - Console output only
- [`enableFileOnly()`](src/logger/Logger.ts:126) - File output only

#### Events

- Emits [`'log'`](src/logger/Logger.ts:31) event with [`LogEntry`](src/logger/types.ts:24)
- Emits [`'error'`](src/logger/Logger.ts:32) event for error handling
- Emits [`'rotate'`](src/logger/Logger.ts:33) event for file rotation

### Usage Examples

```typescript
import { Logger, LogLevel } from 'open-bauth/src/logger';

const logger = new Logger({
  level: LogLevel.INFO,
  enableFile: true,
  logDirectory: './logs',
  format: 'json'
});

// Basic logging
logger.info('user.login', { userId: '123', ip: '192.168.1.1' });

// With additional arguments
logger.error('database.error', 
  { error: 'Connection failed', table: 'users' },
  'Additional context',
  { retryCount: 3 }
);

// Conditional logging
if (logger.shouldLog(LogLevel.DEBUG)) {
  logger.debug('api.details', { 
    method: 'POST', 
    url: '/api/users',
    headers: request.headers 
  });
}

// Runtime configuration change
logger.updateConfig({ level: LogLevel.WARN });
```

## 🔧 Convenience Functions

### Global Access

- [`defaultLogger`](src/logger/index.ts:24) - Global default instance
- [`log`](src/logger/index.ts:27) object with convenience methods
- [`pushLogs(config, event, data)`](src/logger/index.ts:42) - Legacy compatibility

### Usage Examples

```typescript
import { log, defaultLogger } from 'open-bauth/src/logger';

// Using convenience object
log.debug('app.startup', { version: '1.0.0' });
log.info('user.action', { userId: '123', action: 'login' });
log.warn('performance.slow', { endpoint: '/api/data', duration: 2500 });
log.error('api.error', { error: 'Validation failed', code: 400 });

// Accessing default logger directly
defaultLogger.info('custom.message', { custom: 'data' });

// Legacy pushLogs compatibility
pushLogs({ level: 'info' }, 'legacy.event', { data: 'value' });
```

## 📁 File Management

### File Rotation

Automatic file rotation based on size and time:

```typescript
const logger = getLogger({
  enableFile: true,
  logDirectory: './logs',
  maxFileSize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5, // Keep 5 historical files
  datePattern: 'YYYY-MM-DD'
});

// Creates files:
// - app-2024-01-15.log (current)
// - app-2024-01-14.log (previous)
// - app-2024-01-13.log (2nd previous)
// - ...
```

### File Naming

- Based on [`datePattern`](src/logger/config.ts:12) configuration
- Default format: `'YYYY-MM-DD'`
- Directory configurable via [`logDirectory`](src/logger/config.ts:15)
- Custom filename prefix available

### Compression Support

```typescript
const logger = getLogger({
  enableFile: true,
  compress: true, // Compress rotated files
  compressionLevel: 6 // gzip compression level
});
```

## 🔍 Advanced Features

### Event-Driven Architecture

Built on EventEmitter for extensibility:

```typescript
import { getLogger } from 'open-bauth/src/logger';

const logger = getLogger();

// Listen to log events
logger.on('log', (entry: LogEntry) => {
  // Send to external service
  sendToMonitoring(entry);
});

// Listen to error events
logger.on('error', (error: Error) => {
  // Send to error tracking
  sendToErrorTracking(error);
});

// Listen to rotation events
logger.on('rotate', (oldFile: string, newFile: string) => {
  // Notify monitoring system
  notifyRotation(oldFile, newFile);
});
```

### Structured Logging

JSON format with structured data:

```typescript
// Text format output
[2024-01-15 10:30:45] INFO: user.login {"userId":"123","ip":"192.168.1.1"}

// JSON format output
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "event": "user.login",
  "data": {
    "userId": "123",
    "ip": "192.168.1.1"
  },
  "pid": 12345,
  "hostname": "server-01"
}
```

### Performance Monitoring

Built-in performance metrics:

```typescript
import { getLogger } from 'open-bauth/src/logger';

const logger = getLogger({
  enableMetrics: true,
  metricsInterval: 60000 // 1 minute
});

// Access metrics
const metrics = logger.getMetrics();
// {
//   totalLogs: 15420,
//   logsByLevel: { DEBUG: 8900, INFO: 4500, WARN: 1200, ERROR: 800, FATAL: 20 },
//   averageLogSize: 256,
//   bufferUtilization: 0.65,
//   lastRotation: "2024-01-15T09:00:00Z"
// }
```

### Contextual Logging

Add context to all log entries:

```typescript
import { getLogger } from 'open-bauth/src/logger';

const logger = getLogger();

// Set global context
logger.setContext({
  service: 'auth-api',
  version: '2.1.0',
  environment: 'production'
});

// Set request context
logger.setRequestContext({
  requestId: 'req-123',
  userId: 'user-456',
  ip: '192.168.1.1'
});

// All logs now include context
logger.info('user.login', { action: 'login_success' });
// Output includes global and request context
```

## 🎯 Best Practices

### Performance Optimization

1. **Appropriate Log Levels**: Use DEBUG only in development
2. **Structured Data**: Log structured objects for better parsing
3. **Avoid String Concatenation**: Use template literals or object data
4. **Buffer Large Logs**: Use buffering for high-volume logging
5. **Async Operations**: Use async file operations for non-blocking

### Security Considerations

1. **Sanitize Data**: Remove sensitive information from logs
2. **Secure File Permissions**: Restrict log file access
3. **Log Rotation**: Prevent log files from growing too large
4. **Audit Trail**: Maintain audit trail for security events
5. **Error Handling**: Never let logging errors crash application

### Development vs Production

```typescript
// Development configuration
const devConfig = {
  level: LogLevel.DEBUG,
  enableConsole: true,
  enableFile: true,
  format: 'text',
  colors: true,
  includeStackTrace: true
};

// Production configuration
const prodConfig = {
  level: LogLevel.INFO,
  enableConsole: false,
  enableFile: true,
  format: 'json',
  colors: false,
  includeStackTrace: false,
  maxFileSize: 50 * 1024 * 1024,
  maxFiles: 10
};
```

### Monitoring Integration

```typescript
// Integration with monitoring systems
logger.on('log', (entry: LogEntry) => {
  // Send to application monitoring
  if (entry.level >= LogLevel.ERROR) {
    sendToAlerting(entry);
  }
  
  // Send to log aggregation
  sendToLogAggregator(entry);
  
  // Send to metrics collection
  incrementLogCounter(entry.level, entry.event);
});

// Custom formatters for different systems
const elkFormatter = (entry: LogEntry) => ({
  '@timestamp': entry.timestamp,
  '@level': entry.level,
  '@message': entry.event,
  '@fields': entry.data
});

logger.setFormatter('elk', elkFormatter);
```

## 🔧 Integration Examples

### Express.js Integration

```typescript
import express from 'express';
import { getLogger } from 'open-bauth/src/logger';

const app = express();
const logger = getLogger({ service: 'express-api' });

// Request logging middleware
app.use((req, res, next) => {
  logger.setRequestContext({
    requestId: req.headers['x-request-id'],
    method: req.method,
    url: req.url,
    userAgent: req.headers['user-agent']
  });
  
  res.on('finish', () => {
    logger.info('http.request', {
      statusCode: res.statusCode,
      responseTime: Date.now() - req.startTime
    });
  });
  
  next();
});

// Error handling
app.use((err, req, res, next) => {
  logger.error('express.error', {
    error: err.message,
    stack: err.stack,
    url: req.url
  });
  next(err);
});
```

### Microservices Integration

```typescript
import { getLogger } from 'open-bauth/src/logger';

// Service-specific logger
const authServiceLogger = getLogger({
  service: 'auth-service',
  version: '1.2.0',
  enableTracing: true
});

// Distributed tracing
authServiceLogger.setTracing({
  traceId: generateTraceId(),
  spanId: generateSpanId(),
  parentSpanId: getParentSpan()
});

// Correlation across services
authServiceLogger.info('auth.login', {
  traceId: 'trace-123',
  spanId: 'span-456',
  userId: 'user-789'
});
```

### Docker Integration

```typescript
// Docker-friendly configuration
const dockerLogger = getLogger({
  enableConsole: true,
  enableFile: true,
  logDirectory: '/app/logs',
  format: 'json',
  colors: false,
  includeStackTrace: false
});

// Health check endpoint
app.get('/health', (req, res) => {
  const metrics = dockerLogger.getMetrics();
  res.json({
    status: 'healthy',
    logs: {
      total: metrics.totalLogs,
      errors: metrics.logsByLevel.ERROR,
      lastRotation: metrics.lastRotation
    }
  });
});
```

## 📚 API Reference

### Core Types

- [`LogLevel`](src/logger/types.ts:2) - Enum with logging levels
- [`LoggerConfig`](src/logger/types.ts:11) - Configuration interface
- [`LogEntry`](src/logger/types.ts:24) - Log entry structure
- [`LogData`](src/logger/types.ts:34) - Structured log data

### Configuration Functions

- [`createConfig(env)`](src/logger/config.ts:47) - Create environment-based config
- [`mergeConfigs(...configs)`](src/logger/config.ts:89) - Merge multiple configurations
- [`validateConfig(config)`](src/logger/config.ts:102) - Validate configuration object

### Utility Functions

- [`getLogger(config?)`](src/logger/Logger.ts:134) - Get logger instance
- [`setGlobalContext(context)`](src/logger/Logger.ts:145) - Set global context
- [`setRequestContext(context)`](src/logger/Logger.ts:150) - Set request context
- [`clearContext()`](src/logger/Logger.ts:155) - Clear all context

---

See [`src/logger/`](src/logger/) for complete implementation.