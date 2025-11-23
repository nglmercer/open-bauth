// src/middleware/error.handler.ts
import { ErrorHandler } from 'hono';
import { ApiError } from '../api.types';
import { ContentfulStatusCode } from 'hono/utils/http-status';
export const globalErrorHandler: ErrorHandler = (err, c) => {
  if (err instanceof ApiError) {
    const response = err.toResponse();
    return c.json(response, err.statusCode as ContentfulStatusCode);
  }

  // Handle unexpected errors
  console.error('Unhandled Error:', err);
  return c.json(
    {
      error: {
        message: 'An unexpected internal server error occurred.',
      },
    },
    500,
  );
};