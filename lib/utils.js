/**
 * Retrieves the JWKS URI for the specified tenant.
 * @param {string} [tenant='common'] - The tenant to retrieve the JWKS URI for.
 * @returns {Promise<string>} - A promise that resolves with the JWKS URI.
 */
export async function getEntraJwksUri(tenant = 'common') {
  const res = await fetch(`https://login.microsoftonline.com/${tenant}/.well-known/openid-configuration`);
  const data = await res.json();
  return data.jwks_uri;
}