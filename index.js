var crypto = require('crypto');
var Transform = require('readable-stream').Transform;
var inherits = require('inherits');
var immediate = require('immediate');
exports.Authenticate = Authenticate;
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
  crypto.pbkdf2(key, salt, 500, 48, function (err, iv) {
    self._iv = iv.slice(0, 32);
    self._endTag = iv.slice(32);
    var hmac = crypto.createHmac(self._algo, self._iv);
    var chunk = new Buffer(4);
    chunk.writeUInt32BE(self._maxChunkSize, 0);
    hmac.update(chunk);
    self.push(hmac.digest());
    self.push(chunk);
    incr32(self._iv);
    self.emit('iv-ready');
  });
}
Authenticate.prototype._transform = function (chunk, _, next) {
  var self = this;
  this._cache = Buffer.concat([this._cache, chunk]);
  if (this._cache.length < this._minChunkSize) {
    return next();
  }
  if (!this._iv) {
    return this.once('iv-ready', function () {
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
    var header = new Buffer(5);
    
    if (final) {
      hmac.update(this._endTag);
      header.writeUInt8(1, 0);
    } else {
      header.writeUInt8(0, 0);
    }

    header.writeUInt32BE(chunk.length, 1);


    hmac.update(header);

    hmac.update(chunk);
    var out = hmac.digest();
    this.push(out);
    this.push(header);
    this.push(chunk);
    incr32(this._iv);
};
Authenticate.prototype._flush = function (next) {
  var self = this;
  if (!this._iv) {
    return this.once('iv-ready', function () {
      self._flush(next);
    });
  }
  this._sendChunk(this._cache, true);
  fill(this._iv, 0);
  fill(this._endTag, 0);
  next();
};
exports.Verify = Verify;
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
    crypto.pbkdf2(password, salt, 500, 48, function (err, resp) {
      if (err) {
        return cb(err);
      }
      self._iv = resp.slice(0, 32);
      self._endTag = resp.slice(32);
      cb();
    });
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
  if (!this._maxChunkSize) {
    return this._getMaxChunkSize(next, final);
  }
  if (typeof this._chunkSize === 'undefined') {
    return this._getChunkSize(next, final);
  }
  var chunk, hmac, hash, outHash;
  if (this._chunkSize > this._maxChunkSize) {
    return next(new Error('too much data'));
  }
  if (this._final && !final) {
    return next();
  }
  if (this._cache.length >= this._chunkSize) {
    hash = this._currentHash;
    this._currentHash = void 0;
    chunk = this._cache.slice(0,this._chunkSize);
    this._cache = this._cache.slice(this._chunkSize);
    this._chunkSize = void 0;
    hmac = crypto.createHmac(this._algo, this._iv);
    if (final) {
      hmac.update(this._endTag);
    }
    hmac.update(this._chunkBuf);
    this._chunkBuf = void 0;
    hmac.update(chunk);
    outHash = hmac.digest();
    if (compare(hash, outHash)) {
      fill(this._iv, 0);
      return next(new Error('bad data'));
    }
    this.push(chunk);
    incr32(this._iv);
  }
  var self = this;
  if (final) {
    fill(this._iv, 0);
  } else if (this._cache.length) {
    return immediate(function () {
      self._drainCache(next);
    });
  }
  next();
};
Verify.prototype._getChunkSize = function (next, final) {
  if (this._cache.length < this._hashSize + 5) {
    if (final) {
      fill(this._iv, 0);
      return next(new Error('missing data'));
    }
    return next();
  }
  this._currentHash = this._cache.slice(0, this._hashSize);
  var chunk = this._cache.slice(this._hashSize, this._hashSize + 5);
  this._cache = this._cache.slice(this._hashSize + 5);
  this._chunkSize = chunk.readUInt32BE(1);
  this._final = chunk.readUInt8(0);
  this._chunkBuf = chunk;
  if (this._chunkSize > this._maxChunkSize) {
    return next(new Error('invalid block size'));
  }
  this._drainCache(next, final);
};
Verify.prototype._getMaxChunkSize = function (next, final) {
  if (this._cache.length < this._hashSize + 4) {
    if (final) {
      fill(this._iv, 0);
      return next(new Error('missing data'));
    }
    return next();
  }
  var hash = this._cache.slice(0, this._hashSize);
  var chunk = this._cache.slice(this._hashSize, this._hashSize + 4);
  this._cache = this._cache.slice(this._hashSize + 4);
  var hmac = crypto.createHmac(this._algo, this._iv);
  hmac.update(chunk);
  var outHash = hmac.digest();
  if (compare(hash, outHash)) {
    fill(this._iv, 0);
    return next(new Error('bad data'));
  }
  this._maxChunkSize = chunk.readUInt32BE(0);
  incr32(this._iv);
  this._drainCache(next);
};
Verify.prototype._flush = function (next) {
  if (this._error) {
    return next();
  }
  this._drainCache(next, true);
};
function incr32(iv) {
  var len = iv.length;
  var item;
  while (len--) {
    item = iv.readUInt8(len);
    if (item === 255) {
      iv.writeUInt8(0, len);
    } else {
      item++;
      iv.writeUInt8(item, len);
      break;
    }
  }
}
function compare(a, b) {
  var i = -1;
  var len = Math.min(a.length, b.length);
  var out = Math.abs(a.length - b.length);
  while (++i < len) {
    out += (a[i] ^ b[i]);
  }
  return out;
}
function fill(buff, value) {
  var i = -1;
  var len = buff.length;
  while (++i < len) {
    buff[i] = value;
  }
}