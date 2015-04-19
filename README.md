node-rsa-keygen
===============
[![NPM version][npm-image]][npm-url] [![Build Status][travis-image]][travis-url] [![Dependency Status][daviddm-image]][daviddm-url]

Generates a RSA keypair using native OpenSSL library.

This code is loosely based on [ursa](https://github.com/Medium/ursa) RSA generation code.

History
-------
As from node 0.11 the `crypto` library has `publicEncrypt` and `privateDecrypt` functions, we don't need to rely on any external libraries for public-key cryptography.

Usage
----
Install the library:
```sh
npm install --save rsa-keygen
```

```javascript
var rsaKeygen = require('rsa-keygen');
var keys = rsaKeygen.generate();
```

Example
-------
```javascript
var crypto = require('crypto');
var rsaKeygen = require('rsa-keygen');

var keys = rsaKeygen.generate();

var result = crypto.publicEncrypt({
    key: keys.public_key
}, new Buffer('Hello world!'));
// <Crypted Buffer>

var plaintext = crypto.privateDecrypt({
    key: keys.private_key
}, result);
// Hello world!
```

[npm-image]: https://badge.fury.io/js/rsa-keygen.svg
[npm-url]: https://npmjs.org/package/rsa-keygen
[travis-image]: https://travis-ci.org/pagarme/node-rsa-keygen.svg?branch=master
[travis-url]: https://travis-ci.org/pagarme/node-rsa-keygen
[daviddm-image]: https://david-dm.org/pagarme/node-rsa-keygen.svg?theme=shields.io
[daviddm-url]: https://david-dm.org/pagarme/node-rsa-keygen

