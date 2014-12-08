var inherits = require('inherits');

var Transform = require('readable-stream').Transform;

inherits(CipherBase, Transform);
module.exports = CipherBase;
function CipherBase() {
  Transform.call(this);
  this._sync = false;
}
CipherBase.prototype.update = function (data, inputEnd, outputEnc) {
  this._sync = true;
  this.write(data, inputEnd);
  var outData = new Buffer('');
  var chunk;
  while ((chunk = this.read())) {
    outData = Buffer.concat([outData, chunk]);
  }
  if (outputEnc) {
    outData = outData.toString(outputEnc);
  }
  this._sync = false;
  return outData;
};
CipherBase.prototype.final = function (outputEnc) {
  this._sync = true;
  this.end();
  var outData = new Buffer('');
  var chunk;
  var err;
  function onError(e){
    console.log(e);
    err = e;
  }
  this.on('error', onError);
  while ((chunk = this.read())) {
    outData = Buffer.concat([outData, chunk]);
  }
  if (outputEnc) {
    outData = outData.toString(outputEnc);
  }
  this._sync = false;
  return outData;
};
CipherBase.prototype._throwError = function (e, next) {
  if (this._sync) {
    throw e;
  }
  next(e);
};