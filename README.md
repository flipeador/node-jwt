# Node.js JSON Web Tokens

Implementation of [JSON Web Tokens][jwt] (JWT).

JWT is an internet standard for creating data with optional signature whose payload holds JSON that asserts some number of claims.

- Generate, decode, verify and refresh JWTs.
- Generate asymmetric public and private key pairs.
- Signing algorithms: `HS256` `HS384` `HS512` `RS256` `RS384` `RS512`.

#### Standard Claim Fields

| Key  | Name | Description |
| :---: | --- | --- |
| `iss` | Issuer | Entity or provider that issued the token. |
| `sub` | Subject | Entity identified by the token. |
| `aud` | Audience | Recipients that the token is intended for. |
| `exp` | Expiration time | Time after which the token should not be accepted. |
| `iat` | Issued at | Time at which the token has been issued. |

The **time** is the number of seconds that has elapsed since `1970-01-01 00:00:00Z` (Unix time).

> [!CAUTION]
> JWTs may not be suitable for long sessions, tokens should have a shorter lifespan and it can impact user experience.

> [!NOTE]
> This is a lightweight alternative library to [jsonwebtoken][auth0jwt] with no dependencies.

Visit [JWT.io][jwtio] to decode, verify and generate JWTs.

## Installation

```
npm i flipeador/node-jwt#semver:^1.0.0
```

## Examples

<details>
<summary><h4>Symmetric Signing Method</h4></summary>

The same secret key is used to both sign and verify.

```js
import jwt from '@flipeador/node-jwt';

const SECRET = 'HS256_HMAC_SECRET';

const currentTime = Math.floor(Date.now() / 1000);
const maxAge = 86_400; // 1 day (seconds)

const token = jwt.sign(
    // header
    { alg: 'HS256', typ: 'JWT' },
    // payload
    {
        email: 'email@example.com',
        exp: currentTime + maxAge,
        iat: currentTime
    },
    // secret
    SECRET
);

console.log(token);

// Verify signature.
const { payload } = jwt.verify(token, SECRET);

// Verify expiration time.
if (payload.exp <= Date.now() / 1000)
    throw new Error('Expired token');

// Additional verification may be required.
// E.g., Google OAuth requires verification of iss and aud.
if (
    payload.iss !== 'https://accounts.google.com' ||
    payload.aud !== 'MY_APP_GOOGLE_CLIENT_ID'
) { /* throw new Error('Invalid credentials.'); */ }
```

</details>

<details>
<summary><h4>Asymmetric Signing Method</h4></summary>

A pair of private and public keys are used to sign and verify.

```js
import jwt from '@flipeador/node-jwt';

// By default, keys are generated in PEM format.
const { privateKey, publicKey } = await jwt.generateKeyPair();

const token = jwt.sign(
    { alg: 'RS256', typ: 'JWT' }, // header
    { data: 'Hello World!' }, // payload
    // Must use the private key to sign.
    privateKey
);

console.log(token);

// Use the public key to verify.
console.log('verify with public key:',
    jwt.verify(token, publicKey));

// Because public keys can be derived from private keys,
// a private key may be passed instead of a public key.
console.log('verify with private key:',
    jwt.verify(token, privateKey));

// You can combine both PEM keys in the same file and pass them together.
console.log('verify with public+private key:',
    jwt.verify(token, publicKey + privateKey));
```

```js
import jwt from '@flipeador/node-jwt';

const SECRET = 'secret';

// Generate public and private keys in JWK and DER format.
const { privateKey, publicKey } = await jwt.generateKeyPair({
    // JWK keys are exported as a key-value Object.
    publicKeyEncoding: { format: 'jwk' },
    // DER keys are exported as a Buffer.
    privateKeyEncoding: {
        format: 'der',
        // Encrypt the key by specifying a cipher.
        cipher: 'aes-256-cbc',
        passphrase: SECRET,
    }
});

// Since the private key is encrypted, create a KeyObject with the secret.
const privateKeyObject = jwt.createPrivateKey(privateKey, SECRET);

const token = jwt.sign(
    { alg: 'RS256', typ: 'JWT' }, // header
    { data: 'Hello World!' }, // payload
    privateKeyObject
);

console.log(token);
console.log(jwt.verify(token, publicKey));
```

</details>

<details>
<summary><h4>Generate & Refresh</h4></summary>

```js
import { setTimeout } from 'node:timers';
import jwt from '@flipeador/node-jwt';

const currentTime = Math.floor(Date.now() / 1000);
const maxAge = 5; // 5 seconds

const token = jwt.sign(
    { typ: 'JWT' },
    {
        email: 'email@example.com',
        exp: currentTime + maxAge,
        iat: currentTime
    }
);

// The token is refreshed only if:
//   It has not expired.
//   The remaining expiration seconds are less than 25% of maxAge.
// The maxAge is calculated with 'exp - iat' (seconds).
const percent = 25;

console.log(jwt.refresh(token, percent));

setTimeout(() => {
    console.log(jwt.refresh(token, percent));
}, 4000);
```

</details>

## License

This project is licensed under the **Apache License 2.0**. See the [license file](LICENSE) for details.

<!-- REFERENCE LINKS -->
[jwt]: https://en.wikipedia.org/wiki/JSON_Web_Token "JSON Web Token"
[jwtio]: https://jwt.io
[auth0jwt]: https://github.com/auth0/node-jsonwebtoken "@auth0/node-jsonwebtoken"
[ko]: https://nodejs.org/api/crypto.html#class-keyobject
