# JSON Web Token

Implementation of [JSON Web Tokens][jwt] (JWT).

[JWT][jwt] is an internet standard for creating data with optional signature whose payload holds JSON that asserts some number of claims.

- Create, verify and refresh [JWT][jwt]s.
- Generate asymmetric key pairs (public and private).
- Signing Algorithms: `HS256`, `HS384`, `HS512`, `RS256`, `RS384` and `RS512`.

Visit [JWT.io](jwt-io) to decode, verify and generate [JWT][jwt]s.

> **Note**
> - [JWT][jwt]s may not be suitable for long sessions, tokens should have a shorter lifespan and it can impact user experience.
> - This is a lightweight alternative library to [jsonwebtoken][auth0-jwt] with no dependencies.

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     Standard claim fields                                     │
├───────────────────────────────┬─────┬─────────────────────────────────────────────────────────┤
│ Name                          │ Key │ Description                                             │
├───────────────────────────────┼─────┼─────────────────────────────────────────────────────────┤
│ Issuer                        │ iss │ Entity or provider to generate and issue the token.     │
│ Subject                       │ sub │ Entity identified by the token.                         │
│ Audience                      │ aud │ Target audience for the token.                          │
│ Expiry                        │ exp │ Timestamp after which the token should not be accepted. │
│ Issued at                     │ iat │ Date at which the token has been issued.                │
└───────────────────────────────┴─────┴─────────────────────────────────────────────────────────┘
```

## Installation

```
npm install https://github.com/flipeador/node-jwt
```

## Examples

<details>
<summary><h4>Symmetric signing method</h4></summary>

The same secret key is used to both create and verify the signature.

```js
import jwt from '@flipeador/node-jwt';

const secret = 'HS256_HMAC_SECRET';

const token = jwt.sign(
    { alg: 'HS256', typ: 'JWT' }, // header
    { data: 'Hello World!' }, // payload
    secret
);

console.log('token:', token);
console.log('verified:', jwt.verify(token, secret));
```

```
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiSGVsbG8gV29ybGQhIn0.zfVlqtZkpgYY4W_O1WheoqYIZ99zsb3qin4I7kFtDKw
verified: {
  header: { alg: 'HS256', typ: 'JWT' },
  payload: { data: 'Hello World!' }
}
```

</details>

<details>
<summary><h4>Asymmetric encryption method</h4></summary>

A pair of private and public keys are used to encrypt and decrypt the data.

```js
import jwt from '@flipeador/node-jwt';

const { privateKey, publicKey } = await jwt.generateKeyPair();

const token = jwt.sign(
    { alg: 'RS256', typ: 'JWT' }, // header
    { data: 'Hello World!' }, // payload
    privateKey
);

console.log('token:', token);
console.log('verified:', jwt.verify(token, publicKey));
```

</details>

<details>
<summary><h4>Generate and refresh</h4></summary>

```js
import { setTimeout } from 'node:timers';
import jwt from '@flipeador/node-jwt';

const token = jwt.sign(
    { typ: 'JWT' }, // header
    jwt.payload( // payload
        'id',
        'issuer',
        'audience',
        5000, // duration (ms)
        {
            name: 'John Doe',
            email: 'example@email.com'
        }
    )
);

const threshold = 1000;

console.log('token:', token);
console.log('refresh:', jwt.refresh(token, null, threshold));

console.log('-'.repeat(50));

setTimeout(() => {
    const result = jwt.refresh(token, null, threshold);
    // If the token has been updated.
    if (result.updated) {
        const newToken = result.token;
        console.log('newToken:', newToken);
        console.log('refresh:', result);
    }
}, threshold);
```

</details>

## License

This project is licensed under the **GNU General Public License v3.0**. See the [license file](LICENSE) for details.

<!-- REFERENCE LINKS -->
[jwt]: https://en.wikipedia.org/wiki/JSON_Web_Token "JSON Web Token"
[jwt-io]: https://jwt.io/
[auth0-jwt]: https://github.com/auth0/node-jsonwebtoken "@auth0/node-jsonwebtoken"
[envvar]: https://en.wikipedia.org/wiki/Environment_variable "Environment Variable"
