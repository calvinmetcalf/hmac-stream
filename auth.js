var Transform = require('./cipherbase');
var crypto = require('crypto');
var inherits = require('inherits');
var utils = require('./utils');
module.exports = Authenticate;
inherits(Authenticate, Transform);
function Authenticate(key, opts) {
  if (!(this instanceof Authenticate)) {
    return new Authenticate(key, opts);
  }
  Transform.call(this);
  var saltLen = 16;
  var salt = crypto.randomBytes(saltLen);
  this.push(salt);
  this._cache = new Buffer('');
  this._iv = void 0;
  if (typeof opts === 'number') {
    opts = {
      max: opts
    };
  }
  opts = opts || {};
  this._minChunkSize = opts.min || 16;
  this._maxChunkSize = opts.max || 4 * 1024;
  this._algo = 'sha256';
  var self = this;
  var iv = crypto.pbkdf2Sync(key, salt, 500, 48);
  this.setupIv = function (cb) {
    self._iv = iv.slice(0, 32);
    self._endTag = iv.slice(32);
    var hmac = crypto.createHmac(self._algo, self._iv);
    var chunk = new Buffer(4);
    chunk.writeUInt32BE(self._maxChunkSize, 0);
    hmac.update(chunk);
    self.push(hmac.digest());
    self.push(chunk);
    utils.incr32(self._iv);
    cb();
  };

}
Authenticate.prototype._transform = function (chunk, _, next) {
  var self = this;
  this._cache = Buffer.concat([this._cache, chunk]);
  if (this._cache.length < this._minChunkSize) {
    return next();
  }
  if (!this._iv) {
    return this.setupIv(function () {
      self._drainCache(next);
    });
  }
  return this._drainCache(next);
};
Authenticate.prototype._drainCache = function (next) {
  var chunk;
  while (this._cache.length >= this._maxChunkSize) {
    chunk = this._cache.slice(0, this._maxChunkSize);
    this._cache = this._cache.slice(this._maxChunkSize);
    this._sendChunk(chunk);
  }
  if (this._cache.length) {
    chunk = this._cache;
    this._cache = new Buffer('');
    this._sendChunk(chunk);
  }
  next();
};
Authenticate.prototype._sendChunk = function (chunk, final) {
    var hmac = crypto.createHmac(this._algo, this._iv);
    var header = new Buffer(4);
    header.writeUInt32BE(chunk.length, 0);
    if (final) {
      hmac.update(this._endTag);
      header[0] += 128;
    }

    hmac.update(header);

    hmac.update(chunk);
    var out = hmac.digest();
    this.push(out);
    this.push(header);
    this.push(chunk);
    utils.incr32(this._iv);
};
Authenticate.prototype._flush = function (next) {
  var self = this;
  if (!this._iv) {
    return this.once('iv-ready', function () {
      self._flush(next);
    });
  }
  this._sendChunk(this._cache, true);
  utils.fill(this._iv, 0);
  utils.fill(this._endTag, 0);
  next();
};
