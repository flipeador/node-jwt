# Node.js JSON Web Tokens

Implementation of [JSON Web Tokens][jwt] (JWT).

JWT is an internet standard for creating data with optional signature whose payload holds JSON that asserts some number of claims.

- Generate, decode, verify and refresh JWTs.
- Generate asymmetric public and private key pairs.
- Signing algorithms: `HS256 HS384 HS512 RS256 RS384 RS512`.

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

> [!NOTE]
> - JWTs may not be suitable for long sessions, tokens should have a shorter lifespan and it can impact user experience.
> - This is a lightweight alternative library to [jsonwebtoken][auth0jwt] with no dependencies.

Visit [JWT.io][jwtio] to decode, verify and generate JWTs.

## Installation

```
npm i flipeador/node-jwt#semver:^1.0.0
```

## Examples

<details>
<summary><h4>Symmetric signing method</h4></summary>

The same secret key is used to both generate and verify the signature.

```js
import jwt from '@flipeador/node-jwt';

const secret = 'HS256_HMAC_SECRET';

const token = jwt.sign(
    { alg: 'HS256', typ: 'JWT' }, // header
    { data: 'Hello World!' }, // payload
    secret
);

console.log('token:', token);
console.log('verify:', jwt.verify(token, secret));
```

```
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiSGVsbG8gV29ybGQhIn0.zfVlqtZkpgYY4W_O1WheoqYIZ99zsb3qin4I7kFtDKw
verify: {
  header: { alg: 'HS256', typ: 'JWT' },
  payload: { data: 'Hello World!' }
}
```

</details>

<details>
<summary><h4>Asymmetric encryption method</h4></summary>

A pair of private and public keys are used to encrypt and decrypt the data.

Asymmetric keys that are neither a string nor a [KeyObject][ko], are interpreted as a key in the `JWK` format.

```js
import jwt from '@flipeador/node-jwt';

const { privateKey, publicKey } = await jwt.generateKeyPair();

const token = jwt.sign(
    { alg: 'RS256', typ: 'JWT' }, // header
    { data: 'Hello World!' }, // payload
    privateKey
);

console.log('token:', token);
console.log('verify:', jwt.verify(token, publicKey));
```

```
token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiSGVsbG8gV29ybGQhIn0.jjHulHUp7orPVLyprMDnO3e9sk4PRpKKzAiUxe7F5bZoqvq9RX317pRJkrCQT8IFWQVyQXR4qJnJf7442czp40mjjMU7lVBTu8lOmCTbfwWnB-3yzySNX0kZIaCBrwn_LbZBh0AsXPJ3atlSoIFuIEM53OoDMbOTpsuX2B6OkhKuh9bZCpdPMYrkdI4RPrxHVdaaH5V_9geVXPG2LQ8G_zBfJOZfg0jpsmiGfEG_DJjys8TP4EbP7z5ZL7cyR_XooFwzEJKafVxHzgMbvbtCyu2G2xeGxs7Xbv2-4zVqMsTGt5pvNh2ehVp5F6NwMe9chzbujS92dZtsljfTaBjfAA
verify: {
  header: { alg: 'RS256', typ: 'JWT' },
  payload: { data: 'Hello World!' }
}
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
console.log('refresh:', jwt.refresh(token, threshold));

console.log('-'.repeat(50));

setTimeout(() => {
    const result = jwt.refresh(token, threshold);
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

This project is licensed under the **Apache License 2.0**. See the [license file](LICENSE) for details.

<!-- REFERENCE LINKS -->
[jwt]: https://en.wikipedia.org/wiki/JSON_Web_Token "JSON Web Token"
[jwtio]: https://jwt.io
[auth0jwt]: https://github.com/auth0/node-jsonwebtoken "@auth0/node-jsonwebtoken"
[ko]: https://nodejs.org/api/crypto.html#class-keyobject
