'use strict';
var Transform = require('./cipherbase');
var crypto = require('crypto');
var inherits = require('inherits');
var utils = require('./utils');
var debug = require('debug')('streaming-hmac:verify');
module.exports = Verify;
inherits(Verify, Transform);
function Verify(key, aad) {
  if (!(this instanceof Verify)) {
    return new Verify(key, aad);
  }
  if (key.length < 16) {
    throw new TypeError('key must be at lest 128 bits');
  }
  Transform.call(this);
  aad = aad || new Buffer('');
  this._iv = new Buffer(key.length);
  this._iv.fill(0);
  key.copy(this._iv);
  this._algo = 'sha256';
  this._hashSize = 256 / 8;
  this._vstate = 0;
  this._chunkSize = void 0;
  this._currentHash = void 0;
  this._cache = new Buffer('');
  this._len = 0;
  this._flushed = false;
  this._aadHash = crypto.createHmac(this._algo, this._iv);
  this._aadHash.update(aad);
  this._aadHash.update(makeAADLength(aad.length, new Buffer(4)));
  utils.incr32(this._iv);
}

function makeAADLength(num, out) {
  out.writeUInt32BE(num, 0);
  return out;
}
Verify.prototype._stateMachine = function (next) {
  if (this._vstate === 0) {
    if (this._cache.length < this._hashSize) {
      return next();
    }
    var aadHash = this._cache.slice(0, this._hashSize);
    if (utils.areDifferent(this._aadHash.digest(), aadHash)) {
      utils.fill(this._iv, 0);
      this._aadHash = null;
      return next(new Error('bad header'));
    }
    this._aadHash = null;

    this._cache = this._cache.slice(this._hashSize);
    this._vstate = 1;
  }
  var data, hmac, header, hash;
  while (true) {
    switch(this._vstate) {
      case 1:
        if (this._cache.length < this._hashSize + 4) {
          return next();
        }
        header = this._cache.slice(this._hashSize, this._hashSize + 4);
        hash = this._cache.slice(0, this._hashSize);
        debug('headerTag ' + hash.toString('hex'));
        debug('header ' + header.toString('hex'));
        hmac = crypto.createHmac(this._algo, this._iv);
        utils.incr32(this._iv);
        hmac.update(header);

        if (utils.areDifferent(hmac.digest(), hash)) {
          utils.fill(this._iv, 0);
          this._vstate = 3;
          return next(new Error('invalid chunk size'));
        }

        this._chunkSize = header.readUInt32BE(0);
        if (this._chunkSize === 0) {
          return this._final(next);
        }
        this._cache = this._cache.slice(this._hashSize + 4);
        this._vstate = 2;
        if (this._cache.length < this._chunkSize + this._hashSize) {
          return next();
        }
        break;
      case 2:
        if (this._cache.length < this._chunkSize + this._hashSize) {
          return next();
        }
        hash = this._cache.slice(0, this._hashSize);
        data = this._cache.slice(this._hashSize, this._hashSize + this._chunkSize);
        debug('tag ' + hash.toString('hex'));
        debug('chunk ' + data.toString('hex'));
        this._cache = this._cache.slice(this._hashSize + this._chunkSize);

        this._vstate = 1;
        hmac = crypto.createHmac(this._algo, this._iv);
        utils.incr32(this._iv);
        this._chunkSize = 0;
        hmac.update(data);
        if (utils.areDifferent(hmac.digest(), hash)) {
          utils.fill(this._iv, 0);
          this._vstate = 4;
          return next(new Error('bad data'));
        }
        this._len += data.length;
        this.push(data);
        break;
      default:
        return next(new Error('invalid state'));
    }
  }
};
Verify.prototype._final = function(next) {
  this._flushed = true;
  if (this._cache.length > this._hashSize + 4) {
    utils.fill(this._iv, 0);
    this._vstate = 5;
    return next(new Error('too much data'));
  }
  utils.fill(this._iv, 0);
  next();
};

Verify.prototype._transform = function (chunk, _, next) {
  this._cache = Buffer.concat([this._cache, chunk]);
  this._stateMachine(next);
};
Verify.prototype._flush = function (next) {
  if (!this._flushed && this._vstate < 3) {
    this._vstate = 7;
    return next(new Error('missing data'));
  }
  return next();
};
