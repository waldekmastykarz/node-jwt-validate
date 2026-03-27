interface OpenIdConfiguration {
  jwks_uri: string;
}

export enum CloudType {
  Public,
  Ppe,
  USGovernment,
  China
}

/**
 * Retrieves the JWKS URI for the specified tenant.
 * @param {string} [tenant='common'] - The tenant to retrieve the JWKS URI for.
 * @param {CloudType} [cloud=CloudType.Public] - The cloud to retrieve the JWKS URI for.
 * @param {'v1.0' | 'v2.0'} [apiVersion='v2.0'] - The API version of the OpenID configuration endpoint to use.
 * @returns {Promise<string>} - A promise that resolves with the JWKS URI.
 */
export async function getEntraJwksUri(tenant = 'common', cloud: CloudType = CloudType.Public, apiVersion: 'v1.0' | 'v2.0' = 'v2.0'): Promise<string> {
  let cloudUrl = '';
  switch (cloud) {
    case CloudType.Public:
      cloudUrl = 'login.microsoftonline.com';
      break;
    case CloudType.Ppe:
      cloudUrl = 'login.windows-ppe.net';
      break;
    case CloudType.USGovernment:
      cloudUrl = 'login.microsoftonline.us';
      break;
    case CloudType.China:
      cloudUrl = 'login.chinacloudapi.cn';
      break;
  }
  const versionPath = apiVersion === 'v2.0' ? '/v2.0' : '';
  const res = await fetch(`https://${cloudUrl}/${tenant}${versionPath}/.well-known/openid-configuration`);
  const data = (await res.json()) as OpenIdConfiguration;
  return data.jwks_uri;
}