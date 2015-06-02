'use strict';
function incr32(iv) {
  var len = iv.length - 1;
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
exports.incr32 = incr32;
function areDifferent(a, b) {
  // console.log('check');
  // console.log(a.toString('hex'));
  // console.log(b.toString('hex'));
  // constant time equals
  // will leak size of secrete
  // not an issue here as it's always 32 bytes
  var i = -1;
  var len = 32;
  var out = 0;
  if (a.length !== len || a.length !== b.length) {
    return true;
  }
  while (++i < len) {
    out |= (a[i] ^ b[i]);
  }
  return out;
}
exports.areDifferent = areDifferent;
function fill(buff, value) {
  var i = -1;
  var len = buff.length;
  while (++i < len) {
    buff[i] = value;
  }
}
exports.fill = fill;
function numberOfBytes(num) {
  if (num < 255) {
    return 1;
  }
  if (num < 65535) {
    return 2;
  }
  return 4;
}
exports.numberOfBytes = numberOfBytes;

function createHeader(size, val){
  var out = new Buffer(size);
  if (size === 1) {
    out.writeUInt8(val, 0);
  } else if (size === 2) {
    out.writeUInt16BE(val, 0);
  } else {
    out.writeUInt32BE(val, 0);
  }
  return out;
}
exports.createHeader = createHeader;
function readHeader(size, header){
  if (size === 1) {
    return header.readUInt8(0);
  } else if (size === 2) {
    return header.readUInt16BE(0);
  } else {
    return header.readUInt32BE(0);
  }
}
exports.readHeader = readHeader;
function allZero(buf) {
  var len = buf.length;
  var i = -1;
  while (++i < len) {
    if (buf[i] !== 0) {
      return false;
    }
  }
  return true;
}
exports.allZero = allZero;
