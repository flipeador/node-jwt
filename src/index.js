/*
    Implementation of JSON Web Tokens.
    https://github.com/flipeador/node-jwt
*/

import crypto from 'node:crypto';

function safeurl(data)
{
    return data
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/[=]+/gu, '');
}

function unsafeurl(data)
{
    return data
    .replaceAll('-', '+')
    .replaceAll('_', '/');
}

function encode(data)
{
    return safeurl((
        data instanceof Buffer
        ? data
        : Buffer.from(
            typeof(data) === 'object'
                ? JSON.stringify(data)
                : `${data}`
        )
    ).toString('base64'));
}

function decode(data)
{
    return JSON.parse(
        Buffer.from(unsafeurl(data), 'base64')
            .toString('utf8')
    );
}

function detectKeyFormat(key)
{
    if (typeof(key) !== 'string')
        return 'jwk';
    if (key.startsWith('--'))
        return 'pem';
    return 'der';
}

function checkPublicKey(key)
{
    if (key instanceof crypto.KeyObject)
        return key;
    return crypto.createPublicKey({
        key,
        format: detectKeyFormat(key)
    });
}

function checkPrivateKey(key)
{
    if (key instanceof crypto.KeyObject)
        return key;
    return crypto.createPrivateKey({
        key,
        format: detectKeyFormat(key)
    });
}

/**
 * Create a common payload.
 */
export function payload(id, issuer, audience, duration, other)
{
    const timestamp = Date.now();
    return {
        sub: id, // subject
        iss: issuer, // issuer
        aud: audience, // audience
        exp: timestamp + duration, // expiry timestamp
        iat: timestamp, // issued at
        ...other
    };
}

/**
 * Generate an asymmetric public and private key pair.
 * @param modulusLength Key size, in bits.
 */
export function generateKeyPair(modulusLength=2048)
{
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        }, (error, publicKey, privateKey) => {
            if (error) return reject(error);
            resolve({ publicKey, privateKey });
        });
    });
}

function createHmac(header, payload, secret, algorithm)
{
    return safeurl(crypto
        .createHmac(`sha${algorithm.slice(-3)}`, secret)
        .update(`${header}.${payload}`)
        .digest('base64')
    );
}

function verifyHmac(header, payload, signature, secret, algorithm)
{
    return signature === createHmac(header, payload, secret, algorithm);
}

function createSign(header, payload, privateKey, algorithm)
{
    return safeurl(crypto
        .createSign(`RSA-SHA${algorithm.slice(-3)}`)
        .update(`${header}.${payload}`)
        .sign(checkPrivateKey(privateKey), 'base64')
    );
}

function verifySign(header, payload, signature, publicKey, algorithm)
{
    return crypto
    .createVerify(`RSA-SHA${algorithm.slice(-3)}`)
    .update(`${header}.${payload}`)
    .verify(checkPublicKey(publicKey), unsafeurl(signature), 'base64');
}

export function sign(header, payload, secretOrPrivateKey)
{
    if (!secretOrPrivateKey)
        return `${encode(header)}.${encode(payload)}`;
    const eHeader = encode(header);
    const ePayload = encode(payload);
    const signature = header.alg.startsWith('HS')
        ? createHmac(eHeader, ePayload, secretOrPrivateKey, header.alg)
        : createSign(eHeader, ePayload, secretOrPrivateKey, header.alg);
    return `${eHeader}.${ePayload}.${signature}`;
}

export function verify(token, secretOrPublicKey)
{
    token = token.split('.', 3);
    if (token.length < 2 || token.length > 3) return;
    if (secretOrPublicKey && token.length !== 3) return;
    const header = decode(token[0]);
    if (secretOrPublicKey && !(
        header.alg.startsWith('HS')
        ? verifyHmac(...token, secretOrPublicKey, header.alg)
        : verifySign(...token, secretOrPublicKey, header.alg)
    )) return;
    return { header, payload: decode(token[1]) };
}

export function refresh(token, threshold, secretOrPublicKey, privateKey)
{
    const jwt = verify(token, secretOrPublicKey);
    if (!jwt) return;
    if (jwt.payload.exp) { // expiry (timestamp)
        jwt.remaining = jwt.payload.exp - Date.now();
        if (jwt.payload.iat) { // issued at (timestamp)
            jwt.duration = jwt.payload.exp - jwt.payload.iat;
            if (jwt.remaining > 0)
                jwt.updated = jwt.remaining < (jwt.duration - threshold);
        }
    }
    if (jwt.updated) {
        const time = Date.now();
        jwt.payload.exp = time + jwt.duration;
        jwt.payload.iat = time;
        jwt.token = sign(jwt.header, jwt.payload, privateKey??secretOrPublicKey);
    } else
        jwt.token = token;
    return jwt;
}

export default {
    generateKeyPair,
    payload,
    sign,
    verify,
    refresh
};
