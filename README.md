# jwt-validate

[![npm version](https://badge.fury.io/js/jwt-validate.svg)](https://badge.fury.io/js/jwt-validate)

Validate JWT tokens in Node.js.

## Installation

```bash
npm install jwt-validate
```

## Usage

### Validate a Microsoft Entra token

```javascript
import { TokenValidator, getEntraJwksUri } from 'jwt-validate';

// gets the JWKS URL for the Microsoft Entra common tenant
const entraJwksUri = await getEntraJwksUri();

// create a new token validator with the JWKS URL
const validator = new TokenValidator({
  jwksUri: entraJwksUri
});
try {
  // define validation options
  const options = {
    // allowed audience
    audience: '00000000-0000-0000-0000-000000000000',
    // allowed issuer
    issuer: 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0'
  };
  // validate the token
  const validToken = await validator.validateToken(token, options);
  // Token is valid
}
catch (ex) {
  // Token is invalid
  console.error(ex);
}
```

### Validate that the token is an application token

Validate that the token is an application token by checking the `idtyp` claim. Requires the `idtyp` claim to be present in the token.

```javascript
import { TokenValidator, getEntraJwksUri } from 'jwt-validate';

// gets the JWKS URL for the Microsoft Entra common tenant
const entraJwksUri = await getEntraJwksUri();

// create a new token validator with the JWKS URL
const validator = new TokenValidator({
  jwksUri: entraJwksUri
});
try {
  // define validation options
  const options = {
    idtyp: 'app'
  };
  // validate the token
  const validToken = await validator.validateToken(token, options);
  // Token is valid
}
catch (ex) {
  // Token is invalid
  console.error(ex);
}
```

### Validate that the token is a v2.0 token

```javascript
import { TokenValidator, getEntraJwksUri } from 'jwt-validate';

// gets the JWKS URL for the Microsoft Entra common tenant
const entraJwksUri = await getEntraJwksUri();

// create a new token validator with the JWKS URL
const validator = new TokenValidator({
  jwksUri: entraJwksUri
});
try {
  // define validation options
  const options = {
    ver: '2.0'
  };
  // validate the token
  const validToken = await validator.validateToken(token, options);
  // Token is valid
}
catch (ex) {
  // Token is invalid
  console.error(ex);
}
```

## API Reference

### Classes

#### `TokenValidator`

Responsible for validating JWT tokens using JWKS (JSON Web Key Set).

##### Constructor

- `constructor(options)`
  - **Parameters**
    - `options`: Object - Configuration options for the TokenValidator.
      - `cache`: boolean (optional, default=`true`) - Whether to cache the JWKS keys.
      - `cacheMaxAge`: number (optional, default=`86400000`) - The maximum age of the cache in milliseconds (default is 24 hours).
      - `jwksUri`: string - The URI to fetch the JWKS keys from.
  - **Throws**
    - `Error` - If the options parameter is not provided.

##### Methods

- `async validateToken(token, options)`
  - **Description**
    - Validates a JWT token.
  - **Parameters**
    - `token`: string - The JWT token to validate.
    - `options` Object (optional): Validation options. [VerifyOptions](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) from the `jsonwebtoken` library with additional properties.
      - `idtyp` string (optional): The [idtyp](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference#:~:text=set%20as%20well.-,idtyp,-Token%20type) claim to be validated against.
      - `ver`: string (optional) - The version claim to be validated against.
  - **Returns**
    - `Promise<JwtPayload | string>` - The decoded and verified JWT token.
  - **Throws**
    - `Error` - If the token is invalid or the validation fails.

- `clearCache()`
  - **Description**
    - Clears the key cache used by the TokenValidator.
  - **Parameters**
    - None
  - **Returns**
    - None

- `deleteKey(kid)`
  - **Description**
    - Deletes a specific key from the cache.
  - **Parameters**
    - `kid` string - The key ID to delete from the cache.
  - **Returns**
    - None

### Functions

#### `getEntraJwksUri`

- **Description**
  - Gets the JWKS URL for the Microsoft Entra common tenant.
- **Returns**
  - `Promise<string>` - The JWKS URI.

## License

This project is licensed under the [MIT License](LICENSE).
