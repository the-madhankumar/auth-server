import { describe, it, expect } from 'vitest';
import { serializeCookie, parseCookieHeader, readCookie, isJwtExpired } from '../nextjs/internal';

describe('internal utilities', () => {
  describe('serializeCookie', () => {
    it('serializes a basic cookie', () => {
      const result = serializeCookie('test', 'value');
      expect(result).toBe('test=value; Path=/; HttpOnly; SameSite=Lax');
    });

    it('applies options correctly', () => {
      const result = serializeCookie('test', 'value', {
        secure: true,
        maxAge: 3600,
        sameSite: 'strict',
        httpOnly: false,
        path: '/admin'
      });
      expect(result).toBe('test=value; Path=/admin; Max-Age=3600; Secure; SameSite=Strict');
    });
  });

  describe('parseCookieHeader', () => {
    it('parses a standard cookie header', () => {
      const result = parseCookieHeader('foo=bar; baz=qux');
      expect(result).toEqual({ foo: 'bar', baz: 'qux' });
    });

    it('returns empty object for empty header', () => {
      expect(parseCookieHeader('')).toEqual({});
      expect(parseCookieHeader(null)).toEqual({});
      expect(parseCookieHeader(undefined)).toEqual({});
    });
  });

  describe('readCookie', () => {
    it('reads from a Web Request', () => {
      const req = new Request('http://localhost', {
        headers: { Cookie: 'foo=bar; token=123' }
      });
      expect(readCookie(req, 'token')).toBe('123');
    });

    it('reads from a NextRequest-like object', () => {
      const req = {
        cookies: {
          get: (name: string) => (name === 'token' ? { value: '123' } : undefined)
        }
      };
      expect(readCookie(req as any, 'token')).toBe('123');
    });

    it('reads from a raw cookie string', () => {
      expect(readCookie('token=123; foo=bar', 'token')).toBe('123');
    });

    it('reads from a simple map', () => {
      expect(readCookie({ token: '123' }, 'token')).toBe('123');
    });
  });

  describe('isJwtExpired', () => {
    it('returns true for missing or malformed tokens', () => {
      expect(isJwtExpired(undefined)).toBe(true);
      expect(isJwtExpired('')).toBe(true);
      expect(isJwtExpired('not-a-jwt')).toBe(true);
    });

    it('returns false for tokens without an exp claim', () => {
      // payload = {}
      const token = 'header.e30.signature';
      expect(isJwtExpired(token)).toBe(false);
    });

    it('returns true for expired tokens', () => {
      const exp = Math.floor(Date.now() / 1000) - 100; // 100s ago
      const payload = btoa(JSON.stringify({ exp }));
      const token = `header.${payload}.sig`;
      expect(isJwtExpired(token)).toBe(true);
    });

    it('returns false for valid tokens', () => {
      const exp = Math.floor(Date.now() / 1000) + 1000; // 1000s in future
      const payload = btoa(JSON.stringify({ exp }));
      const token = `header.${payload}.sig`;
      expect(isJwtExpired(token)).toBe(false);
    });
  });
});
