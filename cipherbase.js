var inherits = require('inherits');

var Transform = require('readable-stream').Transform;

inherits(CipherBase, Transform);
module.exports = CipherBase;
function CipherBase() {
  Transform.call(this);
}
CipherBase.prototype.update = function (data, inputEnd, outputEnc) {
  this._sync = true;
  this.write(data, inputEnd);
  var outData = new Buffer('');
  var chunk;
  function onError(e){
    throw e;
  }
  this.on('error', onError);
  while ((chunk = this.read())) {
    outData = Buffer.concat([outData, chunk]);
  }
  if (outputEnc) {
    outData = outData.toString(outputEnc);
  }
  this.removeListener('error', onError);
  return outData;
};
CipherBase.prototype.final = function (outputEnc) {
  this.end();
  var outData = new Buffer('');
  var chunk;
  function onError(e){
    throw e;
  }
  this.on('error', onError);
  while ((chunk = this.read())) {
    outData = Buffer.concat([outData, chunk]);
  }
  if (outputEnc) {
    outData = outData.toString(outputEnc);
  }
  this.removeListener('error', onError);
  return outData;
};