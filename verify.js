var Transform = require('./cipherbase');
var crypto = require('crypto');
var inherits = require('inherits');
var utils = require('./utils');
module.exports = Verify;
inherits(Verify, Transform);
function Verify(password) {
  if (!(this instanceof Verify)) {
    return new Verify(password);
  }
  Transform.call(this);
  this._saltLen = 32;
  this._cache = new Buffer('');
  this._iv = void 0;
  this._maxChunkSize = void 0;
  this._chunkSize = void 0;
  this._algo = 'sha256';
  this._hashSize = 256/8;
  this._currentHash = void 0;
  var self = this;
  this._error = void 0;
  this.once('error', function (e) {
    self._error = e;
    if (!self.listeners('error').length) {
      process.nextTick(function () {
        throw e;
      });
    }
  });
  this._makeIv = function (salt, cb) {
    var resp = crypto.pbkdf2Sync(password, salt, 500, 32);
    self._iv = resp;
    cb();
  };
}
Verify.prototype._transform = function (chunk, _, next) {
  if (this._error) {
    return next();
  }
  var self = this;
  this._cache = Buffer.concat([this._cache, chunk]);
  if (!this._iv) {
    if (this._cache.length < this._saltLen) {
      return next();
    }
    var salt = this._cache.slice(0, 16);
    this._cache = this._cache.slice(16);
    return this._makeIv(salt, function (err) {
      if (err) {
        return next(err);
      }
      self._drainCache(next);
    });
  }
  self._drainCache(next);
};
Verify.prototype._drainCache = function (next, final) {
  var chunk, hmac, hash, outHash, gotChunkSize;
  var gotMaxChunkSize = this._getMaxChunkSize(final);
  if (gotMaxChunkSize) {
    if (gotMaxChunkSize === 'done') {
      return next();
    } else {
      return next(gotMaxChunkSize);
    }
  }
  var i = 0;
  while (true) {
    gotChunkSize = this._getChunkSize(final);
    if (gotChunkSize) {
      if (gotChunkSize === 'done') {
        return next();
      } else {
        return next(gotChunkSize);
      }
    }
    if (this._chunkSize > this._maxChunkSize) {
      return next(new Error('too much data'));
    }
    if (this._final && !final) {
      return next();
    }
    if (this._cache.length < this._chunkSize){
      break;
    }
    hash = this._currentHash;
    this._currentHash = void 0;
    chunk = this._cache.slice(0,this._chunkSize);
    this._cache = this._cache.slice(this._chunkSize);
    this._chunkSize = void 0;
    hmac = crypto.createHmac(this._algo, this._iv);
    if (final) {
      //hmac.update(this._endTag);
    }
    hmac.update(this._chunkBuf);
    this._chunkBuf = void 0;
    hmac.update(chunk);
    outHash = hmac.digest();
    if (utils.compare(hash, outHash)) {
      utils.fill(this._iv, 0);
      return next(new Error('bad data'));
    }
    this.push(chunk);
    utils.incr32(this._iv);
    if (final) {
      utils.fill(this._iv, 0);
      break;
    }
  }
  next();
};
Verify.prototype._getChunkSize = function (final) {
  if (typeof this._chunkSize !== 'undefined') {
    return;
  }
  if (this._cache.length < this._hashSize + 4) {
    if (final) {
      utils.fill(this._iv, 0);
      return new Error('missing data');
    }
    return 'done';
  }
  this._currentHash = this._cache.slice(0, this._hashSize);
  var chunk = this._cache.slice(this._hashSize, this._hashSize + 4);
  this._cache = this._cache.slice(this._hashSize + 4);
  this._final = !!(chunk[0] & 0x80);
  if (this._final) {
    chunk[0] -= 128;
  }
  this._chunkSize = chunk.readUInt32BE(0);
  if (this._final) {
    chunk[0] += 128;
  }
  this._chunkBuf = chunk;

  if (this._chunkSize > this._maxChunkSize) {
    return new Error('invalid block size');
  }
};
Verify.prototype._getMaxChunkSize = function (final) {
  if (this._maxChunkSize) {
    return;
  }
  if (this._cache.length < this._hashSize + 4) {
    if (final) {
      utils.fill(this._iv, 0);
      return new Error('missing data');
    }
    return 'done';
  }
  var hash = this._cache.slice(0, this._hashSize);
  var chunk = this._cache.slice(this._hashSize, this._hashSize + 4);
  this._cache = this._cache.slice(this._hashSize + 4);
  var hmac = crypto.createHmac(this._algo, this._iv);
  hmac.update(chunk);
  var outHash = hmac.digest();
  if (utils.compare(hash, outHash)) {
    utils.fill(this._iv, 0);
    return new Error('bad data');
  }
  this._maxChunkSize = chunk.readUInt32BE(0);
  utils.incr32(this._iv);
};
Verify.prototype._flush = function (next) {
  if (this._error) {
    return next();
  }
  this._drainCache(next, true);
};
