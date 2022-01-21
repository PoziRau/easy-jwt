<p align="center">
  <a href="https://pozirau.github.io/easy-jwt/">
    <img src="https://pozirau.github.io/easy-jwt/json.png" alt="json logo" width="255" height="93">
  </a>
</p>

<h3 align="center">Easy JWT</h3>

<p align="center">
  A lightweght JSON Web Token library for node.js
  <br>
  <a href="https://pozirau.github.io/easy-jwt/"><strong>Documentation</strong></a>
  <br>
</p>

## Installation

```bash
npm install easy-jwt
```

## Usage

### [JWT Sign](https://pozirau.github.io/easy-jwt/)

```js
jwt.sign(payload, secret_key, [options])
```

#### Payload & Secret

`payload` could be an object literal, buffer or string representing valid JSON. 

`secret` is a string, buffer or an object containing the secret or encoded private key.

#### Options

`alg` algorithm used for encryption. (Default: `HS512`)

`expireDate` expiry date of JSON Web Token in ms. (No expiry by default)

```js
// Sign using HS256 with 1 hour expiry
var jwt = require('easy-jwt')
var secret = fs.readFileSync('secret.key')
jwt.sign({ foo: 'bar' }, secret, { alg: 'HS256', expires: Date.now() + 3600000 })
```

### [JWT Verify](https://pozirau.github.io/easy-jwt/)

```js
jwt.verify(payload, secret_key, [options])
```

#### Payload & Secret

`payload` JSON Web Token. 

`secret` is a string, buffer or an object containing the secret or encoded private key.

#### Options

`maxAge` maximum age tokens are allowed to be valid after expiry. (No maxAge by default)

`ignoreExpiration` ignore expired token errors. (Default: `False`)

`complete` return header and payload in one JSON object. (Default: `False`)

```js
// Verify JSON Web Token and return header with payload
var jwt = require('easy-jwt')
var secret = fs.readFileSync('secret.key')
jwt.verify(token, secret, { complete: true })
```