'use strict';
var Transform = require('./cipherbase');
var crypto = require('crypto');
var inherits = require('inherits');
var utils = require('./utils');
module.exports = Authenticate;
inherits(Authenticate, Transform);
function Authenticate(key, aad, max) {
  if (!(this instanceof Authenticate)) {
    return new Authenticate(key, max);
  }
  Transform.call(this);
  if (key.length < 16) {
    throw new TypeError('key must be at lest 128 bits');
  }
  this._iv = new Buffer(key.length);
  this._iv.fill(0);
  key.copy(this._iv);
  if (typeof aad === 'number') {
    max = aad;
    aad = void 0;
  }
  aad = aad || new Buffer('');
  this._maxChunkSize = max || Infinity;
  this._algo = 'sha256';
  this._len = 0;
  var hmac = crypto.createHmac(this._algo, this._iv);
  hmac.update(aad);
  var block = new Buffer(4);
  block.writeUInt32BE(aad.length, 0);
  hmac.update(block);
  this.push(hmac.digest());
  utils.incr32(this._iv);
}
Authenticate.prototype._transform = function (data, _, next) {
  var chunk;
  this._len += data.length;
  while (data.length >= this._maxChunkSize) {
    chunk = data.slice(0, this._maxChunkSize);
    data = data.slice(this._maxChunkSize);
    this._sendChunk(chunk);
  }
  if (data.length) {
    chunk = data;
    this._sendChunk(chunk);
  }
  next();
};
Authenticate.prototype._sendChunk = function (chunk) {
  var header = new Buffer(4);
  header.writeUInt32BE(chunk.length, 0);
  var headerTag = crypto.createHmac(this._algo, this._iv)
    .update(header)
    .digest();
  this.push(headerTag);
  this.push(header);
  utils.incr32(this._iv);
  var tag = crypto.createHmac(this._algo, this._iv)
    .update(chunk)
    .digest();
  this.push(tag);
  this.push(chunk);
  utils.incr32(this._iv);
};
Authenticate.prototype._flush = function (next) {
  var chunk = new Buffer(this._headerSize);
  chunk.fill(0);
  var hmac = crypto.createHmac(this._algo, this._iv);
  this.push(hmac.update(chunk).digest());
  this.push(chunk);
  utils.fill(this._iv, 0);
  next();
};
