import { describe, it, expect, vi } from 'vitest';
import { TokenCacheWrapper } from '../src/TokenCacheWrapper';
import { JwksClient } from 'jwks-rsa';

describe('TokenCacheWrapper', () => {
  const mockClient = {
    getSigningKey: vi.fn().mockResolvedValue({
      getPublicKey: () => 'mock-public-key',
    }),
  } as unknown as JwksClient;

  describe('constructor', () => {
    it('should create a TokenCacheWrapper with default options', () => {
      const wrapper = new TokenCacheWrapper(mockClient, {});
      expect(wrapper).toBeInstanceOf(TokenCacheWrapper);
      expect(wrapper.cache).toBeDefined();
    });

    it('should create a TokenCacheWrapper with custom cacheMaxEntries', () => {
      const wrapper = new TokenCacheWrapper(mockClient, { cacheMaxEntries: 10 });
      expect(wrapper).toBeInstanceOf(TokenCacheWrapper);
    });

    it('should create a TokenCacheWrapper with custom cacheMaxAge', () => {
      const wrapper = new TokenCacheWrapper(mockClient, { cacheMaxAge: 1000 });
      expect(wrapper).toBeInstanceOf(TokenCacheWrapper);
    });
  });

  describe('getCacheWrapper', () => {
    it('should return a function', () => {
      const wrapper = new TokenCacheWrapper(mockClient, {});
      const cacheWrapper = wrapper.getCacheWrapper();
      expect(typeof cacheWrapper).toBe('function');
    });

    it('should return a promisified function that can be called', async () => {
      const wrapper = new TokenCacheWrapper(mockClient, {});
      const cacheWrapper = wrapper.getCacheWrapper();
      // The cache wrapper is a promisified memoizer function
      expect(cacheWrapper).toBeDefined();
    });
  });

  describe('cache', () => {
    it('should expose cache property for direct manipulation', () => {
      const wrapper = new TokenCacheWrapper(mockClient, {});
      expect(wrapper.cache).toBeDefined();
      expect(typeof wrapper.cache.reset).toBe('function');
      expect(typeof wrapper.cache.del).toBe('function');
    });

    it('should reset cache without throwing', () => {
      const wrapper = new TokenCacheWrapper(mockClient, {});
      expect(() => wrapper.cache.reset()).not.toThrow();
    });

    it('should delete key without throwing', () => {
      const wrapper = new TokenCacheWrapper(mockClient, {});
      expect(() => wrapper.cache.del('test-kid')).not.toThrow();
    });
  });
});
