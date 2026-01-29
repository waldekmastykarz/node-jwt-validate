import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getEntraJwksUri, CloudType } from '../src/utils';

describe('utils', () => {
  const mockJwksUri = 'https://login.microsoftonline.com/common/discovery/v2.0/keys';

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('CloudType', () => {
    it('should have Public cloud type with value 0', () => {
      expect(CloudType.Public).toBe(0);
    });

    it('should have Ppe cloud type with value 1', () => {
      expect(CloudType.Ppe).toBe(1);
    });

    it('should have USGovernment cloud type with value 2', () => {
      expect(CloudType.USGovernment).toBe(2);
    });

    it('should have China cloud type with value 3', () => {
      expect(CloudType.China).toBe(3);
    });
  });

  describe('getEntraJwksUri', () => {
    it('should fetch JWKS URI for Public cloud with default tenant', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        json: () => Promise.resolve({ jwks_uri: mockJwksUri }),
      } as Response);

      const result = await getEntraJwksUri();

      expect(fetch).toHaveBeenCalledWith('https://login.microsoftonline.com/common/.well-known/openid-configuration');
      expect(result).toBe(mockJwksUri);
    });

    it('should fetch JWKS URI for Public cloud with specific tenant', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        json: () => Promise.resolve({ jwks_uri: mockJwksUri }),
      } as Response);

      const result = await getEntraJwksUri('my-tenant-id');

      expect(fetch).toHaveBeenCalledWith('https://login.microsoftonline.com/my-tenant-id/.well-known/openid-configuration');
      expect(result).toBe(mockJwksUri);
    });

    it('should fetch JWKS URI for Ppe cloud', async () => {
      const ppeJwksUri = 'https://login.windows-ppe.net/common/discovery/v2.0/keys';
      vi.mocked(fetch).mockResolvedValueOnce({
        json: () => Promise.resolve({ jwks_uri: ppeJwksUri }),
      } as Response);

      const result = await getEntraJwksUri('common', CloudType.Ppe);

      expect(fetch).toHaveBeenCalledWith('https://login.windows-ppe.net/common/.well-known/openid-configuration');
      expect(result).toBe(ppeJwksUri);
    });

    it('should fetch JWKS URI for USGovernment cloud', async () => {
      const usGovJwksUri = 'https://login.microsoftonline.us/common/discovery/v2.0/keys';
      vi.mocked(fetch).mockResolvedValueOnce({
        json: () => Promise.resolve({ jwks_uri: usGovJwksUri }),
      } as Response);

      const result = await getEntraJwksUri('common', CloudType.USGovernment);

      expect(fetch).toHaveBeenCalledWith('https://login.microsoftonline.us/common/.well-known/openid-configuration');
      expect(result).toBe(usGovJwksUri);
    });

    it('should fetch JWKS URI for China cloud', async () => {
      const chinaJwksUri = 'https://login.chinacloudapi.cn/common/discovery/v2.0/keys';
      vi.mocked(fetch).mockResolvedValueOnce({
        json: () => Promise.resolve({ jwks_uri: chinaJwksUri }),
      } as Response);

      const result = await getEntraJwksUri('common', CloudType.China);

      expect(fetch).toHaveBeenCalledWith('https://login.chinacloudapi.cn/common/.well-known/openid-configuration');
      expect(result).toBe(chinaJwksUri);
    });
  });
});
