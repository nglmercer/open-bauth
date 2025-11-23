// src/types/api.types.ts
import { AuthError } from "../src/index";

export class ApiError extends Error {
  public authError?: AuthError | any;

  constructor(
    public statusCode: number,
    message: string | AuthError | any,
  ) {
    super(typeof message === "string" ? message : message.message);
    this.name = "ApiError";

    // Store the full error object if it's not a string
    if (typeof message !== "string") {
      this.authError = message;
    }
  }

  toResponse() {
    if (this.authError && typeof this.authError.toResponse === "function") {
      return this.authError.toResponse();
    }
    return {
      success: false,
      error: {
        message: this.message,
      },
    };
  }
}
