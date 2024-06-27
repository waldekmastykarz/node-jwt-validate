# jwt-validate

Validate JWT tokens in Node.js.

[![npm version](https://badge.fury.io/js/jwt-validate.svg)](https://badge.fury.io/js/jwt-validate)

## Installation

```bash
npm install jwt-validate
```

## Usage

### Basic setup

Following snippets show the basic setup for validating JWT tokens in apps that use the CommonJS and ESM module systems. The following sections show specific use cases on top of the basic setup.

#### CommonJS

```javascript
const { TokenValidator, getEntraJwksUri } = require('jwt-validate');

// gets the JWKS URL for the Microsoft Entra common tenant
const entraJwksUri = await getEntraJwksUri();

// create a new token validator with the JWKS URL
const validator = new TokenValidator({
  jwksUri: entraJwksUri
});
try {
  // define validation options
  const options = {
    // ...
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

#### ESM

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
    // ...
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

### Sample use cases

Following are several examples of using the package to validate JWT tokens in different scenarios. For the basic setup see the previous section.

#### Validate a Microsoft Entra token

```javascript
const options = {
  // allowed audience
  audience: '00000000-0000-0000-0000-000000000000',
  // allowed issuer
  issuer: 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0'
};
// validate the token
const validToken = await validator.validateToken(token, options);
```

#### Validate that the token is an application token

Validate that the token is an application token by checking the `idtyp` claim. Requires the `idtyp` claim to be present in the token.

```javascript
const options = {
  idtyp: 'app'
};
// validate the token
const validToken = await validator.validateToken(token, options);
// Token is valid
```

#### Validate that the token is a v2.0 token

```javascript
const options = {
  ver: '2.0'
};
// validate the token
const validToken = await validator.validateToken(token, options);
```

#### Validate a Microsoft Entra token for a multitenant app

```javascript
const options = {
  // list of allowed tenants
  allowedTenants: ['00000000-0000-0000-0000-000000000000'],
  // allowed audience
  audience: '00000000-0000-0000-0000-000000000000',
  // allowed issuer multitenant
  issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0'
};
// validate the token
const validToken = await validator.validateToken(token, options);
```

#### Validate that the token has specified roles or scopes

Validate that the token has one of the specified roles or scopes. This is a common requirements for APIs that support delegated and application permissions and allow usage with several scopes.

```javascript
const options = {
  scp: ['Customers.Read', 'Customers.ReadWrite'],
  roles: ['Customers.Read.All', 'Customers.ReadWrite.All']
};
// validate the token
const validToken = await validator.validateToken(token, options);
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
      - `allowedTenants` string[] (optional): The allowed tenants for the JWT token. Compared against the `tid` claim.
      - `idtyp` string (optional): The [idtyp](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference#:~:text=set%20as%20well.-,idtyp,-Token%20type) claim to be validated against.
      - `roles` string[] (optional): Roles expected in the 'roles' claim in the JWT token.
      - `scp` string[] (optional): Scopes expected in the 'scp' claim in the JWT token.
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

#### `getEntraJwksUri(tenant)`

- **Description**
  - Gets the JWKS URL for the Microsoft Entra common tenant.
- **Parameters**
  - `tenant` string (optional, default=`common`) - The tenant to get the JWKS URL for.
- **Returns**
  - `Promise<string>` - The JWKS URI.

## License

This project is licensed under the [MIT License](LICENSE).
