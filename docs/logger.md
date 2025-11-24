# Logger System

The library includes a production-ready, flexible logging system built on [`EventEmitter`](node:events) with support for console/file output, rotation, JSON/text formats, colors, and configurable levels.

## Features
- **Log Levels**: DEBUG (0), INFO (1), WARN (2), ERROR (3), FATAL (4), SILENT (5)
- **Outputs**: Console, file rotation (size/date-based)
- **Formats**: Colored text (console), JSON/text (file)
- **Singleton**: `getLogger()` for global instance
- **Convenience**: `log.debug()`, `log.info()` etc.
- **Configurable**: Environment-based presets (dev/prod/test)

## Installation & Usage

Import from library:
```typescript
import { getLogger, log, LogLevel } from 'open-bauth';
```

### Basic Usage
```typescript
const logger = getLogger();

// Structured logging
logger.info('user.login', { 
  userId: '123', 
  ip: '192.168.1.1',
  context: { sessionId: 'abc' } 
});

logger.error('auth.failed', new Error('Invalid credentials'));

// Convenience functions
log.warn('rate.limit.exceeded', { attempts: 5 });
log.fatal('server.shutdown', { reason: 'OOM' });
```

### Configuration
```typescript
const logger = getLogger({
  level: LogLevel.DEBUG,
  enableFile: true,
  logDirectory: './logs',
  maxFileSize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5,
  format: 'json', // or 'text'
  includeStackTrace: true
});
```

Environment presets via [`createConfig`](src/logger/config.ts:47):
- `development`: DEBUG, console+file
- `production`: INFO, file only, JSON
- `test`: WARN, silent
- `silent`: No output

## API Reference

### [`Logger`](src/logger/Logger.ts:9) Class
- `debug(event, data?)`, `info()`, `warn()`, `error()`, `fatal()`
- `updateConfig(config)`
- `silence()`, `unsilence(level?)`
- `enableConsoleOnly()`, `enableFileOnly()`
- Events: `'log'` emits [`LogEntry`](src/logger/types.ts:24)

### Convenience
- `defaultLogger`
- `log` object with methods
- `pushLogs(config, event, data)` compatibility

## File Rotation
- Daily files: `app-YYYY-MM-DD.log`
- Size limit: rotate at `maxFileSize`
- Retention: keep `maxFiles`

## Example Output

**Console (colored)**:
```
[2024-01-15 10:30:45] INFO [user.login] User logged in
Data: {"userId":"123","ip":"192.168.1.1"}
Context: {"sessionId":"abc"}
```

**File (JSON)**:
```json
{"timestamp":"2024-01-15T10:30:45.123Z","level":"INFO","event":"user.login","message":"User logged in","data":{"userId":"123"}}
```

## Best Practices
- Use structured `data` and `context`
- Set `level: LogLevel.WARN` in tests
- Production: file-only, JSON format
- Listen to `'log'` for external sinks (e.g., Sentry)

See [`src/logger/`](src/logger/) for implementation.