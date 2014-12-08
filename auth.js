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
  this._iv = new Buffer(key.length + 8);
  this._iv.fill(0);
  key.copy(this._iv);
  if (typeof aad === 'number') {
    max = aad;
    aad = void 0;
  }
  aad = aad || new Buffer('');
  this._maxChunkSize = max || 4 * 1024;
  this._headerSize = utils.numberOfBytes(this._maxChunkSize);
  this._algo = 'sha256';
  this._len = 0;
  var hmac = crypto.createHmac(this._algo, this._iv);
  hmac.update(aad);
  var block = new Buffer(8);
  block.writeUInt32BE(aad.length, 0);
  block.writeUInt32BE(this._maxChunkSize, 4);
  hmac.update(block);
  this.push(hmac.digest());
  this.push(block);
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
    var hmac = crypto.createHmac(this._algo, this._iv);
    var header = utils.createHeader(this._headerSize, chunk.length);
    hmac.update(header);
    hmac.update(chunk);
    var out = hmac.digest();
    this.push(out);
    this.push(header);
    this.push(chunk);
    utils.incr32(this._iv);
};
Authenticate.prototype._flush = function (next) {
  var chunk = new Buffer(this._headerSize);
  chunk.fill(0xff);
  var lenChunk = new Buffer(4);
  lenChunk.writeUInt32BE(this._len, 0);
  var hmac = crypto.createHmac(this._algo, this._iv);
  this.push(hmac.update(lenChunk).digest());
  this.push(chunk);
  utils.fill(this._iv, 0);
  next();
};
