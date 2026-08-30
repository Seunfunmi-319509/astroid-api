import 'reflect-metadata';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ExecutionContext, CallHandler } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { of } from 'rxjs';
import { SensitivePayloadInterceptor } from './sensitive-payload.interceptor';
import { SENSITIVE_FIELDS_KEY } from '../decorators/sensitive.decorator';

function buildMockContext(overrides: {
  body?: Record<string, unknown>;
  metaKey?: string;
  metaValue?: unknown;
} = {}) {
  const req = {
    body: overrides.body ?? null,
  };

  // Create actual function targets so Reflect metadata can be attached.
  const handler = () => {};
  const targetClass = class {};

  if (overrides.metaKey) {
    Reflect.defineMetadata(overrides.metaKey, overrides.metaValue, handler);
  }

  return {
    switchToHttp: () => ({
      getRequest: () => req,
      getResponse: () => ({}),
    }),
    getHandler: () => handler,
    getClass: () => targetClass,
  } as unknown as ExecutionContext;
}

function buildCallHandler(returnValue: unknown = { id: '1', token: 'secret-123' }): CallHandler {
  return { handle: () => of(returnValue) };
}

describe('SensitivePayloadInterceptor', () => {
  let reflector: Reflector;
  let interceptor: SensitivePayloadInterceptor;

  beforeEach(() => {
    vi.clearAllMocks();
    reflector = new Reflector();
    interceptor = new SensitivePayloadInterceptor(reflector);
  });

  describe('response redaction', () => {
    it('should redact built-in sensitive fields from response', async () => {
      const ctx = buildMockContext({ metaKey: SENSITIVE_FIELDS_KEY, metaValue: [] });
      const response = {
        id: 'user-1',
        password: 'hunter2',
        token: 'jwt-secret-token',
        secret: 'api-secret',
        name: 'Alice',
      };
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toEqual({
        id: 'user-1',
        password: '[REDACTED]',
        token: '[REDACTED]',
        secret: '[REDACTED]',
        name: 'Alice',
      });
    });

    it('should redact nested sensitive fields in response', async () => {
      const ctx = buildMockContext({ metaKey: SENSITIVE_FIELDS_KEY, metaValue: [] });
      const response = {
        user: {
          id: 'u-1',
          credentials: {
            accessToken: 'abc123',
            refreshToken: 'def456',
            safe: 'visible',
          },
        },
      };
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toEqual({
        user: {
          id: 'u-1',
          credentials: {
            accessToken: '[REDACTED]',
            refreshToken: '[REDACTED]',
            safe: 'visible',
          },
        },
      });
    });

    it('should redact sensitive fields in array responses', async () => {
      const ctx = buildMockContext({ metaKey: SENSITIVE_FIELDS_KEY, metaValue: [] });
      const response = [
        { id: '1', apiKey: 'key-1', name: 'App 1' },
        { id: '2', apiKey: 'key-2', name: 'App 2' },
      ];
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toEqual([
        { id: '1', apiKey: '[REDACTED]', name: 'App 1' },
        { id: '2', apiKey: '[REDACTED]', name: 'App 2' },
      ]);
    });

    it('should pass through null/undefined response', async () => {
      const ctx = buildMockContext({ metaKey: SENSITIVE_FIELDS_KEY, metaValue: [] });
      const next = buildCallHandler(null);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toBeNull();
    });

    it('should not mutate the original response object', async () => {
      const ctx = buildMockContext({ metaKey: SENSITIVE_FIELDS_KEY, metaValue: [] });
      const response = { id: '1', password: 'secret' };
      const next = buildCallHandler(response);

      await interceptor.intercept(ctx, next).toPromise();

      // Original should be untouched
      expect(response.password).toBe('secret');
    });
  });

  describe('request body redaction', () => {
    it('should redact sensitive fields from incoming request body', async () => {
      const ctx = buildMockContext({
        body: { username: 'alice', password: 'hunter2', token: 'abc' },
        metaKey: SENSITIVE_FIELDS_KEY,
        metaValue: [],
      });
      const next = buildCallHandler({ ok: true });

      await interceptor.intercept(ctx, next).toPromise();

      // The body should have been mutated in-place
      const req = (ctx.switchToHttp() as { getRequest(): { body: Record<string, unknown> } }).getRequest();
      expect(req.body.password).toBe('[REDACTED]');
      expect(req.body.token).toBe('[REDACTED]');
      expect(req.body.username).toBe('alice');
    });
  });

  describe('custom fields via @Sensitive() decorator', () => {
    it('should redact extra fields specified in @Sensitive(["custom"])', async () => {
      const ctx = buildMockContext({
        metaKey: SENSITIVE_FIELDS_KEY,
        metaValue: ['ssn', 'taxId'],
      });
      const response = {
        id: '1',
        ssn: '123-45-6789',
        taxId: 'AB-12345',
        name: 'Alice',
      };
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toEqual({
        id: '1',
        ssn: '[REDACTED]',
        taxId: '[REDACTED]',
        name: 'Alice',
      });
    });

    it('should combine built-in and custom fields', async () => {
      const ctx = buildMockContext({
        metaKey: SENSITIVE_FIELDS_KEY,
        metaValue: ['creditCard'],
      });
      const response = {
        id: '1',
        password: 'secret',
        creditCard: '4111-1111-1111-1111',
        name: 'Alice',
      };
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toEqual({
        id: '1',
        password: '[REDACTED]',
        creditCard: '[REDACTED]',
        name: 'Alice',
      });
    });

    it('should still redact built-in fields when @Sensitive() has no extra fields', async () => {
      const ctx = buildMockContext({
        metaKey: SENSITIVE_FIELDS_KEY,
        metaValue: [],
      });
      const response = { id: '1', secret: 's3cr3t', name: 'Bob' };
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toEqual({
        id: '1',
        secret: '[REDACTED]',
        name: 'Bob',
      });
    });
  });

  describe('no-op when @Sensitive() is absent', () => {
    it('should pass through without redaction when decorator is not present', async () => {
      const ctx = buildMockContext();
      const response = { id: '1', password: 'secret', token: 'abc' };
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      // No redaction — the response should be untouched
      expect(result).toEqual({ id: '1', password: 'secret', token: 'abc' });
    });

    it('should not redact request body when decorator is absent', async () => {
      const ctx = buildMockContext({
        body: { password: 'hunter2', username: 'alice' },
      });
      const next = buildCallHandler({ ok: true });

      await interceptor.intercept(ctx, next).toPromise();

      const req = (ctx.switchToHttp() as { getRequest(): { body: Record<string, unknown> } }).getRequest();
      expect(req.body.password).toBe('hunter2');
    });
  });

  describe('field matching', () => {
    it('should match field names case-insensitively', async () => {
      const ctx = buildMockContext({
        metaKey: SENSITIVE_FIELDS_KEY,
        metaValue: [],
      });
      const response = {
        PASSWORD: 'secret1',
        Secret: 'secret2',
        Token: 'secret3',
        safe: 'ok',
      };
      const next = buildCallHandler(response);

      const result = await interceptor.intercept(ctx, next).toPromise();

      expect(result).toEqual({
        PASSWORD: '[REDACTED]',
        Secret: '[REDACTED]',
        Token: '[REDACTED]',
        safe: 'ok',
      });
    });
  });
});
