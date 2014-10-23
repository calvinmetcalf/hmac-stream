var crypto = require('crypto');
var Transform = require('readable-stream').Transform;
var inherits = require('inherits');
exports.Authenticate = Authenticate;
inherits(Authenticate, Transform);
function Authenticate(key, chunkSize) {
  if (!(this instanceof Authenticate)) {
    return new Authenticate(key);
  }
    Transform.call(this);
  var saltLen = 16;
  var salt = crypto.randomBytes(saltLen);
  this.push(salt);
  this._cache = new Buffer('');
  this._iv = void 0;
  this._chunkSize = chunkSize || 512;
  this._algo = 'sha256';
  var self = this;
  crypto.pbkdf2(key, salt, 500, 32, function (err, iv) {
    self._iv = iv;
    var hmac = crypto.createHmac(self._algo, self._iv);
    var chunk = new Buffer(4);
    chunk.writeUInt32BE(self._chunkSize, 0);
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
  if (this._cache.length < this._chunkSize) {
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
  var chunk, hmac;
  while (this._cache.length > this._chunkSize) {
    chunk = this._cache.slice(0, this._chunkSize);
    this._cache = this._cache.slice(this._chunkSize);
    hmac = crypto.createHmac(this._algo, this._iv);
    hmac.update(chunk);
    this.push(hmac.digest());
    this.push(chunk);
    incr32(this._iv);
  }
  next();
};
Authenticate.prototype._flush = function (next) {
  if (!this._cache.length) {
    fill(this._iv, 0);
    return next();
  }
  var self = this;
  if (!this._iv) {
    return this.once('iv-ready', function () {
      self._flush(next);
    });
  }
  var chunk = this._cache;
  var hmac = crypto.createHmac(this._algo, this._iv);
  hmac.update(chunk);
  this.push(hmac.digest());
  this.push(chunk);
  fill(this._iv, 0);
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
  this._chunkSize = void 0;
  this._algo = 'sha256';
  this._hashSize = 256/8;
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
    crypto.pbkdf2(password, salt, 500, this._saltLen, function (err, resp) {
      if (err) {
        return cb(err);
      }
      self._iv = resp;
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
Verify.prototype._drainCache = function (next) {
  if (!this._chunkSize) {
    return this._getChunkSize(next);
  }
  var blockSize = this._chunkSize + this._hashSize;
  var chunk, hmac, hash, outHash;
  while (this._cache.length > blockSize) {
    hash = this._cache.slice(0, this._hashSize);
    chunk = this._cache.slice(this._hashSize, blockSize);
    this._cache = this._cache.slice(blockSize);
    hmac = crypto.createHmac(this._algo, this._iv);
    hmac.update(chunk);
    outHash = hmac.digest();
    if (compare(hash, outHash)) {
      fill(this._iv, 0);
      return next(new Error('bad data'));
    }
    this.push(chunk);
    incr32(this._iv);
  }
  next();
};
Verify.prototype._getChunkSize = function (next) {
  if (this._cache.length < this._hashSize + 4) {
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
  this._chunkSize = chunk.readUInt32BE(0);
  incr32(this._iv);
  this._drainCache(next);
};
Verify.prototype._flush = function (next) {
  if (this._error) {
    return next();
  }
  if (!this._cache.length) {
    fill(this._iv, 0);
    return next();
  }
  if (this._cache.length <= this._hashSize) {
    fill(this._iv, 0);
    return new Error('missing data');
  }
  var hash = this._cache.slice(0, this._hashSize);
  var chunk = this._cache.slice(this._hashSize);
  var hmac = crypto.createHmac(this._algo, this._iv);
  hmac.update(chunk);
  var outHash = hmac.digest();
  if (compare(hash, outHash)) {
    fill(this._iv, 0);
    return next(new Error('bad data'));
  }
  this.push(chunk);
  fill(this._iv, 0);
  next();
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