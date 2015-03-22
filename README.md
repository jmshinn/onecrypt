## onecrypt

onecrypt provides a simple, limited API for encryption.  The main idea is to avoid options and just let you pass in your data.

The main functionality:
* Symmetric encryption/decryption with AES (*)
* Secure symmetric cipher key generation
* Secure password hashing for storage and verification with [scrypt](http://en.wikipedia.org/wiki/Scrypt)
* Upgrading from insecure hash+salt passwords to scrypt
* ... and a few other hashing methods

## Installation

    $ npm install onecrypt

## Usage
### [Secure Key Generation](https://github.com/jmshinn/onecrypt/wiki/Secure-Key-Generation)
The first step in encryption/decryption is generating secure keys.

From the command line, where this will most likely be used:
```js
$ node
> var onecrypt = require('./lib/onecrypt');
> var key = onecrypt.gen_key();
> var mackey = onecrypt.gen_key();
```
... at which point, you can copy/paste or otherwise store your keys however makes sense.

**_BE AWARE_ this is a point of vulnerability, where you store your key must be secure in its own right.  If you copy the key to your clipboard, you'll want to clear it out of your clipboard when you're done with it.**

[See the full docs](https://github.com/jmshinn/onecrypt/wiki/Secure-Key-Generation) for more options and the ability to generate a key from a password.

### [AES Encryption/Decryption](https://github.com/jmshinn/onecrypt/wiki/AES-Encryption-Decryption)
Once you have your keys

***

Whither onecrypt?
=================
Using encryption effectively is a bit like a scavenger hunt:

> If you should desire security
>
> Then you must find these answers three
>
> And when you fail I'll laugh at thee
>
> Your efforts undone by `ECB`

Security is tough.  node.js provides a fairly comprehensive library for security and cryptography in the form of the built-in [`crypto`](http://nodejs.org/api/crypto.html) module.  The problem with comprehensive tools is that they give you lots of rope with which to hang yourself.

The reason security is tough is because there are bunches of options which can be combined in an extraordinary number of ways.  Innocuous sounding things like "salt" and "padding" seem to be superfluous, but getting them wrong will open up critical flaws in your implementation, and could compromise your actual security completely.

The methods and options used in this module are based heavily on [Colin Percival's *Cryptographic Right Answers*](http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html).  I'm personally no expert on cryptography (oh, sure, I spent a few torrid afternoons with the [Chinese Remainder Theorem](http://en.wikipedia.org/wiki/Chinese_remainder_theorem) back in my college days, but nothing too substantial), which means that I'm not the guy who can break this stuff, but I can wrap my head around the recommendations of the people who can, and I've tried to use that knowledge to provide a limited set of tools that perform their responsibilities without opening up security holes.

## <span style="color:#c00;">But Wait, There's More</span>
<strong style="color:#c00;">You *should not*, under any circumstance, consider this module a replacement for SSL/TLS/HTTPS when trying to secure communications between a browser and a server.  If SSL is available to you, use it and move on.  If you don't want to pay for a certificate, there are places that provide them for free, or you can do a self signed certificate that would suffice under some circumstances.  If your communication is worth securing and traditional SSL encryption is an option, it's most likely the best option even if it's not free.  There are specific scenarios where this module is appropriate, but you should feel sufficiently warned that this is not a way to avoid SSL.  To put it as simply as possible, this module can at most be as secure as SSL, but never more secure and (simply due to lack of extensive review) likely less, because at its heart it's using the node built in crypto module which is itself based on... OpenSSL.  It's far less tested and has had fewer eyes reviewing it and hands making sure it stays up to date.</strong>
