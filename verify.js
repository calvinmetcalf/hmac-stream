var Transform = require('./cipherbase');
var crypto = require('crypto');
var inherits = require('inherits');
var utils = require('./utils');
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
  key.copy(this._iv);
  this._algo = 'sha256';
  this._hashSize = 256/8;
  this._vstate = 0;
  this._maxChunkSize = void 0;
  this._chunkSize = void 0;
  this._currentHash = void 0;
  this._cache = new Buffer('');
  this._len = 0;
  this._aadHash = crypto.createHmac(this._algo, this._iv);
  this._aadHash.update(aad);
  this._aadHash.update(makeBlock(aad.length));
  utils.incr32(this._iv);
}

Verify.prototype._stateMachine = function (next) {
  if (this._vstate === 0) {
    if (this._cache.length < this._hashSize + 8) {
      return next();
    }
    var aadHash = this._cache.slice(0, this._hashSize);
    var aadsize = this._cache.slice(this._hashSize, this._hashSize + 4);
    var maxBlockSize = this._cache.slice(this._hashSize + 4, this._hashSize + 8);
    this._aadHash.update(maxBlockSize);
    if (utils.compare(this._aadHash.digest(), aadHash)) {
      utils.fill(this._iv, 0);
      return next(new Error('bad header'));
    }
    this._maxChunkSize = maxBlockSize.readUInt32BE(0);
    this._cache = this._cache.slice(this._hashSize + 8);
    this._vstate = 1;
    this.addHash = null;
  }
  var data, hmac;
  while (true) {
    switch(this._vstate) {
      case 1: 
        if (this._cache.length < this._hashSize + 4) {
          return next();
        }
        if (this._cache[this._hashSize] === 0xff) {
          return this._final(next);
        }
        this._currentHash = this._cache.slice(0, this._hashSize);
        this._chunkSize = this._cache.readUInt32BE(this._hashSize);
        if (this._chunkSize > this._maxChunkSize) {
          utils.fill(this._iv, 0);
          this._vstate = 3;
          return next(new Error('invalid chunk size'));
        }
        this._cache = this._cache.slice(this._hashSize + 4);
        this._vstate = 2;
        if (this._cache.length < this._chunkSize) {
          return next();
        }
        break;
      case 2: 
        if (this._cache.length < this._chunkSize) {
          return next();
        }
        data = this._cache.slice(0, this._chunkSize);
        this._cache = this._cache.slice(this._chunkSize);

        this._vstate = 1;
        hmac = crypto.createHmac(this._algo, this._iv);
        utils.incr32(this._iv);
        hmac.update(makeBlock(this._chunkSize));
        this._chunkSize = 0;
        hmac.update(data);
        if (utils.compare(hmac.digest(), this._currentHash)) {
          utils.fill(this._iv, 0);
          this._vstate = 4;
          return next(new Error('bad data'));
        }
        this._len += data.length;
        this.push(data);
        break;
      default: 
        return next(new Error('should not get here'));
    }
  }
};
Verify.prototype._final = function(next) {
  if (this._cache.length > this._hashSize  + 4) {
    utils.fill(this._iv, 0);
    this._vstate = 5;
    return next(new Error('too much data'));
  }
  var hash = this._cache.slice(0, this._hashSize);
  var hmac = crypto.createHmac(this._algo, this._iv);
  utils.fill(this._iv, 0);
  if (utils.compare(hmac.update(makeBlock(this._len)).digest(), hash)) {
    this._vstate = 6;
    return next(new Error('missing data'));
  }
  next();
};
var out = new Buffer(4);
function makeBlock(num) {
  out.writeUInt32BE(num, 0);
  return out;
}
Verify.prototype._transform = function (chunk, _, next) {
  this._cache = Buffer.concat([this._cache, chunk]);
  this._stateMachine(next);
};