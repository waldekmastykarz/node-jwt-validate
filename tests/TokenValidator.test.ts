import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import jwt from 'jsonwebtoken';
import { TokenValidator, ValidateTokenOptions, EntraJwtPayload } from '../src/TokenValidator';

// Mock jsonwebtoken
vi.mock('jsonwebtoken', async () => {
  const actual = await vi.importActual('jsonwebtoken');
  return {
    ...actual as object,
    default: {
      ...actual as object,
      decode: vi.fn(),
      verify: vi.fn(),
    },
  };
});

// Mock jwks-rsa
vi.mock('jwks-rsa', () => ({
  default: vi.fn(() => ({
    getSigningKey: vi.fn().mockResolvedValue({
      getPublicKey: () => 'mock-public-key',
    }),
  })),
}));

describe('TokenValidator', () => {
  const validJwksUri = 'https://login.microsoftonline.com/common/discovery/v2.0/keys';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('constructor', () => {
    it('should throw an error if options is not provided', () => {
      expect(() => new TokenValidator(undefined as any)).toThrow('options is required');
    });

    it('should create a TokenValidator with valid options', () => {
      const validator = new TokenValidator({ jwksUri: validJwksUri });
      expect(validator).toBeInstanceOf(TokenValidator);
    });

    it('should create a TokenValidator with cache disabled', () => {
      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: false });
      expect(validator).toBeInstanceOf(TokenValidator);
    });

    it('should create a TokenValidator with custom cache max age', () => {
      const validator = new TokenValidator({ jwksUri: validJwksUri, cacheMaxAge: 1000 });
      expect(validator).toBeInstanceOf(TokenValidator);
    });
  });

  describe('validateToken', () => {
    let validator: TokenValidator;

    beforeEach(() => {
      validator = new TokenValidator({ jwksUri: validJwksUri, cache: false });
    });

    it('should throw an error for malformed token', async () => {
      vi.mocked(jwt.decode).mockReturnValue(null);
      
      await expect(validator.validateToken('invalid-token')).rejects.toThrow('jwt malformed');
    });

    it('should validate a valid token without options', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123' },
        signature: 'test-signature',
      };
      const verifiedPayload = { sub: 'user-123' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token');
      expect(result).toEqual(verifiedPayload);
    });

    it('should validate a token with idtyp claim', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', idtyp: 'app' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', idtyp: 'app' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token', { idtyp: 'app' });
      expect(result).toEqual(verifiedPayload);
    });

    it('should throw an error for invalid idtyp claim', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', idtyp: 'user' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', idtyp: 'user' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      await expect(validator.validateToken('valid-token', { idtyp: 'app' }))
        .rejects.toThrow('jwt idtyp is invalid. Expected: app');
    });

    it('should validate a token with ver claim', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', ver: '2.0' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', ver: '2.0' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token', { ver: '2.0' });
      expect(result).toEqual(verifiedPayload);
    });

    it('should throw an error for invalid ver claim', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', ver: '1.0' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', ver: '1.0' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      await expect(validator.validateToken('valid-token', { ver: '2.0' }))
        .rejects.toThrow('jwt ver is invalid. Expected: 2.0');
    });

    it('should validate a token with scp claim', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', scp: ['read', 'write'] },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', scp: ['read', 'write'] };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token', { scp: ['read'] });
      expect(result).toEqual(verifiedPayload);
    });

    it('should throw an error if required scopes are missing', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', scp: ['read'] },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', scp: ['read'] };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      await expect(validator.validateToken('valid-token', { scp: ['admin'] }))
        .rejects.toThrow('jwt does not contain any of the required scopes');
    });

    it('should validate a token with roles claim', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', roles: ['admin', 'user'] },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', roles: ['admin', 'user'] };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token', { roles: ['admin'] });
      expect(result).toEqual(verifiedPayload);
    });

    it('should throw an error if required roles are missing', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', roles: ['user'] },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', roles: ['user'] };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      await expect(validator.validateToken('valid-token', { roles: ['admin'] }))
        .rejects.toThrow('jwt does not contain any of the required roles');
    });

    it('should validate a token with both scp and roles when scp is present in token', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', scp: ['read'] },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', scp: ['read'] };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token', { scp: ['read'], roles: ['admin'] });
      expect(result).toEqual(verifiedPayload);
    });

    it('should validate a token with both scp and roles when roles is present in token', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', roles: ['admin'] },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', roles: ['admin'] };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token', { scp: ['read'], roles: ['admin'] });
      expect(result).toEqual(verifiedPayload);
    });

    it('should validate a token with allowedTenants', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', tid: 'tenant-123' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', tid: 'tenant-123' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token', { allowedTenants: ['tenant-123', 'tenant-456'] });
      expect(result).toEqual(verifiedPayload);
    });

    it('should throw an error if tenant is not allowed', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', tid: 'tenant-789' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', tid: 'tenant-789' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      await expect(validator.validateToken('valid-token', { allowedTenants: ['tenant-123', 'tenant-456'] }))
        .rejects.toThrow('jwt tid is not allowed. Allowed tenants: tenant-123, tenant-456');
    });

    it('should throw an error if tid is missing when allowedTenants is specified', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      await expect(validator.validateToken('valid-token', { allowedTenants: ['tenant-123'] }))
        .rejects.toThrow('jwt tid is not allowed');
    });

    it('should update issuer with tenantId placeholder', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', tid: 'tenant-123' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', tid: 'tenant-123' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const options: ValidateTokenOptions = { issuer: 'https://sts.windows.net/{tenantId}/' };
      await validator.validateToken('valid-token', options);
      
      expect(options.issuer).toBe('https://sts.windows.net/tenant-123/');
    });

    it('should update issuer array with tenantId placeholder', async () => {
      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123', tid: 'tenant-123' },
        signature: 'test-signature',
      };
      const verifiedPayload: EntraJwtPayload = { sub: 'user-123', tid: 'tenant-123' };
      
      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const options: ValidateTokenOptions = { issuer: ['https://sts.windows.net/{tenantId}/', 'https://login.microsoftonline.com/{tenantId}/v2.0'] };
      await validator.validateToken('valid-token', options);
      
      expect(options.issuer).toEqual(['https://sts.windows.net/tenant-123/', 'https://login.microsoftonline.com/tenant-123/v2.0']);
    });
  });

  describe('key rotation retry', () => {
    it('should retry after clearing cache when SigningKeyNotFoundError is thrown', async () => {
      const signingKeyNotFoundError = new Error('Unable to find a signing key');
      signingKeyNotFoundError.name = 'SigningKeyNotFoundError';

      const mockGetSigningKey = vi.fn()
        .mockRejectedValueOnce(signingKeyNotFoundError)
        .mockResolvedValueOnce({ getPublicKey: () => 'new-public-key' });

      const jwksClientMod = await import('jwks-rsa');
      vi.mocked(jwksClientMod.default).mockReturnValueOnce({
        getSigningKey: mockGetSigningKey,
      } as any);

      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: true });

      const decodedToken = {
        header: { kid: 'rotated-kid', alg: 'RS256' },
        payload: { sub: 'user-123' },
        signature: 'test-signature',
      };
      const verifiedPayload = { sub: 'user-123' };

      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);
      vi.mocked(jwt.verify).mockReturnValue(verifiedPayload as any);

      const result = await validator.validateToken('valid-token');
      expect(result).toEqual(verifiedPayload);
    });

    it('should throw when retry also fails with SigningKeyNotFoundError', async () => {
      const signingKeyNotFoundError = new Error('Unable to find a signing key');
      signingKeyNotFoundError.name = 'SigningKeyNotFoundError';

      const mockGetSigningKey = vi.fn()
        .mockRejectedValue(signingKeyNotFoundError);

      const jwksClientMod = await import('jwks-rsa');
      vi.mocked(jwksClientMod.default).mockReturnValueOnce({
        getSigningKey: mockGetSigningKey,
      } as any);

      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: true });

      const decodedToken = {
        header: { kid: 'unknown-kid', alg: 'RS256' },
        payload: { sub: 'user-123' },
        signature: 'test-signature',
      };

      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);

      await expect(validator.validateToken('valid-token'))
        .rejects.toThrow('Unable to find a signing key');
    });

    it('should not retry for non-SigningKeyNotFoundError errors', async () => {
      const genericError = new Error('Network error');

      const mockGetSigningKey = vi.fn()
        .mockRejectedValue(genericError);

      const jwksClientMod = await import('jwks-rsa');
      vi.mocked(jwksClientMod.default).mockReturnValueOnce({
        getSigningKey: mockGetSigningKey,
      } as any);

      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: true });

      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123' },
        signature: 'test-signature',
      };

      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);

      await expect(validator.validateToken('valid-token'))
        .rejects.toThrow('Network error');
    });

    it('should not retry when cache is disabled', async () => {
      const signingKeyNotFoundError = new Error('Unable to find a signing key');
      signingKeyNotFoundError.name = 'SigningKeyNotFoundError';

      const mockGetSigningKey = vi.fn()
        .mockRejectedValue(signingKeyNotFoundError);

      const jwksClientMod = await import('jwks-rsa');
      vi.mocked(jwksClientMod.default).mockReturnValueOnce({
        getSigningKey: mockGetSigningKey,
      } as any);

      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: false });

      const decodedToken = {
        header: { kid: 'test-kid', alg: 'RS256' },
        payload: { sub: 'user-123' },
        signature: 'test-signature',
      };

      vi.mocked(jwt.decode).mockReturnValue(decodedToken as any);

      await expect(validator.validateToken('valid-token'))
        .rejects.toThrow('Unable to find a signing key');
      // Should only be called once (no retry without cache)
      expect(mockGetSigningKey).toHaveBeenCalledTimes(1);
    });
  });

  describe('cache management', () => {
    it('should clear cache when clearCache is called', () => {
      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: true });
      expect(() => validator.clearCache()).not.toThrow();
    });

    it('should delete key when deleteKey is called', () => {
      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: true });
      expect(() => validator.deleteKey('test-kid')).not.toThrow();
    });

    it('should not throw when clearing cache on validator with cache disabled', () => {
      const validator = new TokenValidator({ jwksUri: validJwksUri, cache: false });
      expect(() => validator.clearCache()).not.toThrow();
    });
  });
});
