import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, map } from 'rxjs';
import { Request } from 'express';
import { SENSITIVE_FIELDS_KEY } from '../decorators/sensitive.decorator';

/**
 * Default fields that are always redacted when a route is marked @Sensitive().
 * Case-insensitive matching is applied.
 */
const BUILTIN_SENSITIVE_FIELDS = new Set([
  'password',
  'passwordhash',
  'password_hash',
  'secret',
  'secretkey',
  'secret_key',
  'privatekey',
  'private_key',
  'refreshtoken',
  'refresh_token',
  'accesstoken',
  'access_token',
  'token',
  'apikey',
  'api_key',
  'hashedkey',
  'hashed_key',
  'webhooksecret',
  'webhook_secret',
  'hmacsecret',
  'hmac_secret',
  'creditcard',
  'credit_card',
  'cardnumber',
  'card_number',
  'cvv',
  'ssn',
  'social_security',
  'bankaccount',
  'bank_account',
  'routingnumber',
  'routing_number',
]);

/**
 * NestJS interceptor that redacts sensitive fields from both request and
 * response payloads for routes decorated with @Sensitive().
 *
 * This provides an additional layer of protection beyond audit logging:
 * it actively scrubs data from HTTP responses before they reach the client,
 * ensuring credentials, tokens, and financial identifiers never leak.
 *
 * The interceptor is designed to be applied selectively via the @Sensitive()
 * decorator — it is NOT registered globally to avoid unnecessary overhead
 * on non-sensitive routes.
 *
 * @example
 * // Per-route usage
 * @Sensitive()
 * @Post('auth/login')
 * login(@Body() dto: LoginDto) { ... }
 *
 * @example
 * // With extra custom fields
 * @Sensitive(['ssn', 'taxId'])
 * @Get('users/:id/profile')
 * getProfile(@Param('id') id: string) { ... }
 *
 * @example
 * // Controller-level decoration
 * @Sensitive()
 * @Controller('auth')
 * export class AuthController { ... }
 */
@Injectable()
export class SensitivePayloadInterceptor implements NestInterceptor {
  constructor(private readonly reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    // Read extra field names from the @Sensitive() decorator metadata.
    // If no @Sensitive() decorator is present, this interceptor is a no-op
    // so it can safely be registered globally without overhead.
    const extraFields = this.reflector.getAllAndOverride<string[]>(SENSITIVE_FIELDS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Not a sensitive route — pass through without redaction.
    if (extraFields === undefined) {
      return next.handle();
    }

    // Merge built-in + extra fields into a single redaction set (lowercased).
    const fieldsToRedact = new Set(
      [...BUILTIN_SENSITIVE_FIELDS, ...extraFields].map((f) => f.toLowerCase()),
    );

    // Redact sensitive fields from the incoming request body.
    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    if (req.body && typeof req.body === 'object') {
      // Mutate in place — the body is already parsed and won't be re-read
      // by other interceptors in the same pipeline.
      this.redactInPlace(req.body, fieldsToRedact);
    }

    // Redact sensitive fields from the outgoing response body.
    return next.handle().pipe(
      map((data) => {
        if (data === null || data === undefined) {
          return data;
        }
        // Deep-clone to avoid mutating cached/shared objects.
        return this.redactDeepClone(data, fieldsToRedact);
      }),
    );
  }

  /**
   * Recursively redacts fields in-place on the given object. Arrays and
   * nested objects are traversed. Primitive values are left untouched.
   */
  private redactInPlace(data: unknown, fields: Set<string>): void {
    if (data === null || data === undefined || typeof data !== 'object') {
      return;
    }

    if (Array.isArray(data)) {
      for (const item of data) {
        this.redactInPlace(item, fields);
      }
      return;
    }

    const obj = data as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      if (fields.has(key.toLowerCase())) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        this.redactInPlace(obj[key], fields);
      }
    }
  }

  /**
   * Returns a deep clone of `data` with sensitive fields replaced by
   * `[REDACTED]`. The original is never mutated.
   */
  private redactDeepClone(data: unknown, fields: Set<string>): unknown {
    if (data === null || data === undefined) {
      return data;
    }

    if (Array.isArray(data)) {
      return data.map((item) => this.redactDeepClone(item, fields));
    }

    if (typeof data === 'object') {
      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
        if (fields.has(key.toLowerCase())) {
          result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
          result[key] = this.redactDeepClone(value, fields);
        } else {
          result[key] = value;
        }
      }
      return result;
    }

    return data;
  }
}
