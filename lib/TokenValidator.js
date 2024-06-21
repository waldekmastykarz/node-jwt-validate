import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { TokenCacheWrapper } from './TokenCacheWrapper.js';

class TokenValidator {
  #client;
  #cacheWrapper;

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

    const cache = options.cache ?? true;

    this.#client = jwksClient({
      cache,
      cacheMaxAge: options.cacheMaxAge ?? 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      jwksUri: options.jwksUri
    });
    if (cache) {
      this.#cacheWrapper = new TokenCacheWrapper();
      this.#client.getSigningKey = this.#cacheWrapper.cacheWrapper(this.#client, options);
    }
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

  /**
   * Clears the cache used by the TokenValidator.
   */
  clearCache() {
    this.#cacheWrapper?.cache.reset();
  }

  /**
   * Deletes a key from the cache.
   * @param {string} kid The key ID to delete from the cache.
   */
  deleteKey(kid) {
    this.#cacheWrapper?.cache.del(kid);
  }

  async #getSigningKey(kid) {
    const key = await this.#client.getSigningKey(kid);
    return key.getPublicKey();
  }
}

export { TokenValidator };