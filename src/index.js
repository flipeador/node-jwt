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
    .replace(/[=]+$/u, '');
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
    if (typeof(key) === 'string')
        return 'pem';
    if (key instanceof Uint8Array)
        return 'der';
    return 'jwk';
}

export function createPublicKey(key, format, type='spki')
{
    if (key instanceof crypto.KeyObject)
        return key;
    format ??= detectKeyFormat(key);
    return crypto.createPublicKey({ key, format, type });
}

export function createPrivateKey(key, passphrase, format, type='pkcs8')
{
    if (key instanceof crypto.KeyObject)
        return key;
    format ??= detectKeyFormat(key);
    return crypto.createPrivateKey({ key, format, type, passphrase });
}

/**
 * Generate an asymmetric public and private key pair.
 */
export function generateKeyPair(options={}) {
    if (typeof(options) === 'number')
        options = { modulusLength: options };
    options.modulusLength ??= 2048;
    options.publicKeyEncoding ??= { };
    options.publicKeyEncoding.type ??= 'spki';
    options.publicKeyEncoding.format ??= 'pem';
    options.privateKeyEncoding ??= { };
    options.privateKeyEncoding.type ??= 'pkcs8';
    options.privateKeyEncoding.format ??= 'pem';
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', options,
            (error, publicKey, privateKey) => {
                if (error) return reject(error);
                resolve({ publicKey, privateKey });
            }
        );
    });
}

function signHMAC(header, payload, secret, algorithm)
{
    return safeurl(crypto
        .createHmac(`sha${algorithm.slice(-3)}`, secret)
        .update(`${header}.${payload}`)
        .digest('base64')
    );
}

function verifyHMAC(header, payload, signature, secret, algorithm)
{
    return crypto.timingSafeEqual(
        crypto.createHmac(`sha${algorithm.slice(-3)}`, secret)
        .update(`${header}.${payload}`)
        .digest(),
        Buffer.from(unsafeurl(signature), 'base64')
    );
}

function signRSA(header, payload, privateKey, algorithm)
{
    return safeurl(crypto
        .createSign(`RSA-SHA${algorithm.slice(-3)}`)
        .update(`${header}.${payload}`)
        .sign(createPrivateKey(privateKey), 'base64')
    );
}

function verifyRSA(header, payload, signature, publicKey, algorithm)
{
    return crypto
    .createVerify(`RSA-SHA${algorithm.slice(-3)}`)
    .update(`${header}.${payload}`)
    .verify(createPublicKey(publicKey), unsafeurl(signature), 'base64');
}

export function sign(header, payload, secretOrPrivateKey)
{
    if (!secretOrPrivateKey)
        return `${encode(header)}.${encode(payload)}`;
    const eHeader = encode(header);
    const ePayload = encode(payload);
    const signature = header.alg.startsWith('HS')
        ? signHMAC(eHeader, ePayload, secretOrPrivateKey, header.alg)
        : signRSA(eHeader, ePayload, secretOrPrivateKey, header.alg);
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
        ? verifyHMAC(...token, secretOrPublicKey, header.alg)
        : verifyRSA(...token, secretOrPublicKey, header.alg)
    )) return;
    return { header, payload: decode(token[1]) };
}

export function refresh(token, percent, privateKey)
{
    const jwt = verify(token, privateKey);
    if (!jwt) return;
    jwt.token = token;
    if (jwt.payload.exp) {
        const currentTime = Math.floor(Date.now() / 1000);
        jwt.remaining = jwt.payload.exp - currentTime;
        if (jwt.payload.iat && jwt.remaining > 0) {
            jwt.duration = jwt.payload.exp - jwt.payload.iat;
            jwt.updated = jwt.remaining < (jwt.duration * percent / 100);
            if (jwt.updated) {
                jwt.payload.exp = currentTime + jwt.duration;
                jwt.payload.iat = currentTime;
                jwt.token = sign(jwt.header, jwt.payload, privateKey);
            }
        }
    }
    return jwt;
}

export default {
    createPublicKey,
    createPrivateKey,
    generateKeyPair,
    sign,
    verify,
    refresh
};
