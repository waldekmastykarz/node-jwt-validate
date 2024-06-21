import createDebug from 'debug';
const logger = createDebug('jwt-validate');
import memoizer from 'lru-memoizer';
import { promisify, callbackify } from 'util';

// Based on https://github.com/auth0/node-jwks-rsa/blob/4fe372be935c2aa0882e0f1e58d33eead4be966d/src/wrappers/cache.js
// exposes cache to make it possible to clear cache and keys
class TokenCacheWrapper {
  cacheWrapper(client, { cacheMaxEntries = 5, cacheMaxAge = 600000 }) {
    logger(`Configured caching of signing keys. Max: ${cacheMaxEntries} / Age: ${cacheMaxAge}`);
    this.cache = memoizer({
      hash: (kid) => kid,
      load: callbackify(client.getSigningKey.bind(client)),
      maxAge: cacheMaxAge,
      max: cacheMaxEntries
    });
    return promisify(this.cache);
  }
}

export { TokenCacheWrapper };