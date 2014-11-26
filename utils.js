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
exports.incr32 = incr32;
function compare(a, b) {
  var i = -1;
  var len = Math.min(a.length, b.length);
  var out = Math.abs(a.length - b.length);
  while (++i < len) {
    out += (a[i] ^ b[i]);
  }
  return out;
}
exports.compare = compare;
function fill(buff, value) {
  var i = -1;
  var len = buff.length;
  while (++i < len) {
    buff[i] = value;
  }
}
exports.fill = fill;