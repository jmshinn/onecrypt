var crypto = require('crypto'),
	util = require('util');

var fn = require('./fn');

// a one stop shop to do symmetric encryption that makes the "right" choices (for a general case)
var encipher = exports.encipher = function(payload, key, mackey, opts, cb) {
	if (typeof opts === 'function') cb = opts, opts = {};
	else opts = opts || {};

	var iv_length = 128; // bit length

	// this operates async because we may need to build our own IV from a cryptographically secure source

	// we don't expect this, but if there's a reason to generate the IV outside the application we can allow it
	if (opts.iv) {
		// we should update this to also check to make sure it meets our iv_length
		var iv;
		if (!Buffer.isBuffer(opts.iv)) iv = opts.iv_encoding?new Buffer(opts.iv, opts.iv_encoding):new Buffer(opts.iv);
		else iv = opts.iv;

		if (cb) setImmediate(function() { _encipher(payload, key, mackey, iv, opts, cb); });
		else return _encipher(payload, key, mackey, iv, opts);
	}
	else {
		if (cb) crypto.randomBytes(iv_length/8, function(err, iv) { if (err) return cb(err); _encipher(payload, key, mackey, iv, opts, cb); });
		else {
			var iv = crypto.randomBytes(iv_length/8);
			if (util.isError(iv)) return err;
			else return _encipher(payload, key, mackey, iv, opts);
		}
	}
};

// we have to do this assymmetrically with a callback so that we can properly handle creating a random IV at runtime
var _encipher = function(payload, key, mackey, iv, opts, cb) {
	// for now, force the cipher used and mode
	opts.algorithm = 'aes-256';
	opts.mode = 'ctr';
	opts.hmac_algo = 'sha512';

	if (!Buffer.isBuffer(payload)) payload = opts.payload_encoding?new Buffer(payload, opts.payload_encoding):new Buffer(payload);
	if (!Buffer.isBuffer(key)) key = opts.key_encoding?new Buffer(key, opts.key_encoding):new Buffer(key);
	if (!Buffer.isBuffer(mackey)) mackey = opts.mackey_encoding?new Buffer(mackey, opts.mackey_encoding):new Buffer(mackey);

	var cipher = crypto.createCipheriv(opts.algorithm+'-'+opts.mode, key, iv);
	cipher.write(payload);
	cipher.end();
	var ciphertext = cipher.read();

	var hmac = crypto.createHmac(opts.hmac_algo, mackey);
	hmac.write(iv);
	hmac.write(ciphertext);
	hmac.end();
	var mac = hmac.read();

	// send all of the public data needed to decrypt the message, the calling application can handle how they're packaged together
	if (cb) cb(null, [mac, iv, ciphertext]);
	else return [mac, iv, ciphertext];
};

// a one stop shop to do symmetric decryption, companion to our `encipher()` function, that makes the "right" choices (for a general case)
var decipher = exports.decipher = function(payload, key, mackey, mac, iv, opts) {
	opts = opts || {};

	// we pass in the pieces individually, the calling application manages how the iv and mac are packaged together
	// for now, force the cipher used and mode
	opts.algorithm = 'aes-256';
	opts.mode = 'ctr';
	opts.hmac_algo = 'sha512';

	if (!Buffer.isBuffer(payload)) payload = opts.payload_encoding?new Buffer(payload, opts.payload_encoding):new Buffer(payload);
	if (!Buffer.isBuffer(key)) key = opts.key_encoding?new Buffer(key, opts.key_encoding):new Buffer(key);
	if (!Buffer.isBuffer(mackey)) mackey = opts.mackey_encoding?new Buffer(mackey, opts.mackey_encoding):new Buffer(mackey);
	if (!Buffer.isBuffer(iv)) iv = opts.iv_encoding?new Buffer(iv, opts.iv_encoding):new Buffer(iv);
	if (!Buffer.isBuffer(mac)) mac = opts.mac_encoding?new Buffer(mac, opts.mac_encoding):new Buffer(mac);

	var hmac = crypto.createHmac(opts.hmac_algo, mackey);
	hmac.write(iv);
	hmac.write(payload);
	hmac.end();
	// if we haven't authenticated, then we've got a problem
	if (!fn.constant_time_str_cmp(hmac.read().toString(opts.mac_encoding), mac.toString(opts.mac_encoding))) return new Error('Message failed to authenticate');

	var decipher = crypto.createDecipheriv(opts.algorithm+'-'+opts.mode, key, iv);
	decipher.write(payload);
	decipher.end();
	var plaintext = decipher.read();
	return plaintext; // return a raw buffer of our decrypted text
};