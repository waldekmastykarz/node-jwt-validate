import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

class TokenValidator {
  /**
   * Constructs a new instance of TokenValidator.
   * @param {Object} options Configuration options for the TokenValidator.
   * @param {boolean} [options.cache=true] Whether to cache the JWKS keys.
   * @param {number} [options.cacheMaxAge=86400000] The maximum age of the cache in milliseconds (default is 24 hours).
   * @param {string} options.jwksUri The URI to fetch the JWKS keys from.
   * @throws {Error} If the options parameter is not provided.
   */
  constructor(options) {
    if (!options) {
      throw new Error('options is required');
    }

    this.client = jwksClient({
      cache: options.cache ?? true,
      cacheMaxAge: options.cacheMaxAge ?? 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      jwksUri: options.jwksUri
    });
  }

  /**
   * Validates a JWT token.
   * @param {string} token The JWT token to validate.
   * @param {import('jsonwebtoken').VerifyOptions & { complete?: false } & { idtyp?: string, ver?: string }} [options] Validation options.
   * @property {string} [options.idtyp] The expected value of the 'idtyp' claim in the JWT token.
   * @property {string} [options.ver] The expected value of the 'ver' claim in the JWT token.
   * @returns {Promise<import('jsonwebtoken').JwtPayload | string>} The decoded and verified JWT token.
   * @throws {Error} If the token is invalid or the validation fails.
   */
  async validateToken(token, options) {
    const decoded = jwt.decode(token, { complete: true });
    const key = await this.#getSigningKey(decoded.header.kid);
    const verifiedToken = jwt.verify(token, key, options);

    if (options?.idtyp &&
      options.idtyp !== verifiedToken.idtyp) {
      throw new Error(`jwt idtyp is invalid. expected: ${options.idtyp}`);
    }

    if (options?.ver &&
      options.ver !== verifiedToken.ver) {
      throw new Error(`jwt ver is invalid. expected: ${options.ver}`);
    }

    return verifiedToken;
  }

  async #getSigningKey(kid) {
    const key = await this.client.getSigningKey(kid);
    return key.getPublicKey();
  }
}

export { TokenValidator };