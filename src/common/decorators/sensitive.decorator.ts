import { SetMetadata } from '@nestjs/common';

export const IS_SENSITIVE_KEY = 'astroid:isSensitive';
export const SENSITIVE_FIELDS_KEY = 'astroid:sensitiveFields';

/**
 * Marks a route or controller as handling sensitive data.
 *
 * When applied, the `SensitivePayloadInterceptor` will automatically redact
 * sensitive fields from both request and response payloads. Optionally accepts
 * a list of additional field names to redact beyond the built-in defaults.
 *
 * @example
 * // Redact built-in sensitive fields (password, token, secret, etc.)
 * @Sensitive()
 * @Post('auth/login')
 * login(@Body() dto: LoginDto) { ... }
 *
 * @example
 * // Redact built-in fields PLUS custom ones
 * @Sensitive(['ssn', 'creditCard', 'bankAccount'])
 * @Post('users')
 * createUser(@Body() dto: CreateUserDto) { ... }
 *
 * @example
 * // Apply to an entire controller
 * @Sensitive()
 * @Controller('auth')
 * export class AuthController { ... }
 */
export const Sensitive = (...extraFields: string[]) =>
  SetMetadata(SENSITIVE_FIELDS_KEY, extraFields);
