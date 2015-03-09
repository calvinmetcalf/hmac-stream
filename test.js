'use strict';
var test = require('tape');
var crypto = require('crypto');
var auth = require('./');
var utils = require('./utils');
test('works', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key);
  var val = new auth.Verify(key);
  var out = '';
  val.on('data', function (d) {
    out += d.toString();
  }).on('finish', function () {
    t.ok(auterData.length < 1000, 'correct length');
    t.equals(data, out);
  });
  var auterData = new Buffer('');
  auther.pipe(val);
  auther.on('data', function (d) {
    auterData = Buffer.concat([auterData, d]);
  });
  auther.write(new Buffer(data));
  auther.end();
});
test('works2', function (t) {
  t.plan(1);
  var data1 = new Buffer(16);
  data1.fill(8);
  var data2 = new Buffer(16);
  data2.fill(4);
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = '';
  val.on('data', function (d) {
    out += d.toString('hex');
  }).on('finish', function () {
    t.equals(Buffer.concat([data1, data2]).toString('hex'), out);
  });
  var auterData = new Buffer('');
  auther.pipe(val);
  auther.on('data', function (d) {
    auterData = Buffer.concat([auterData, d]);
  });
  auther.write(data1);
  auther.write(data2);
  auther.end();
});
test('works3', function (t) {
  t.plan(1);
  var data1 = new Buffer(16);
  data1.fill(8);
  var data2 = new Buffer(16);
  data2.fill(4);
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = '';
  out += val.update(auther.update(data1)).toString('hex');
  out += val.update(auther.update(data2)).toString('hex');
  out += val.update(auther.final()).toString('hex');
  out += val.final().toString('hex');
  t.equals(Buffer.concat([data1, data2]).toString('hex'), out);
});

test('errors', function (t) {
  t.plan(1);
  var data1 = new Buffer(16);
  data1.fill(8);
  var data2 = new Buffer(16);
  data2.fill(4);
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = '';
  out += val.update(auther.update(data1)).toString('hex');
  out += val.update(auther.update(data2)).toString('hex');
  t.throws(val.final.bind(val), /Error/,'throws');
});
test('errors2', function (t) {
  t.plan(1);
  var data1 = new Buffer(16);
  data1.fill(8);
  var data2 = new Buffer(16);
  data2.fill(4);
  var data3 =  new Buffer(50);
  data3.fill(1);
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = '';
  out += val.update(auther.update(data1)).toString('hex');
  out += val.update(auther.update(data2)).toString('hex');
  t.throws(val.update.bind(val,data3), /Error/,'throws');
});
function getBuffer(len) {
  var b = new Buffer(len);
  b.fill(len);
  return b;
}
test('errors if the last chunk is lost', function (t) {
  t.plan(1);
  var data1 = new Buffer(32);
  data1.fill(8);
  var data2 = new Buffer(16);
  data2.fill(4);
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = new Buffer('');
  val.on('data', function (d) {
    out = Buffer.concat([out, d]);
  }).on('end', function () {
    //t.ok(false);
  }).on('error', function (e) {
    t.equals(e.message, 'missing data', 'should error');
  });
  var auterData  = new Buffer('');
  var ended = false;
  auther.on('data', function (d) {
    if(ended === true) {
      //console.log('after end', d);
      return;
    }
    val.write(d);
    if (d.toString('hex') === '04040404040404040404040404040404') {
      //console.log('ending');
      ended = true;
      val.end(function (err){
        //console.log('ended', err);
      });
    }
    auterData = Buffer.concat([auterData, d]);
  });
  auther.on('end', function () {
    if (!ended){
      val.end();
    }
  });
  auther.write(data1);
  auther.write(data2);
  auther.end();
});
test('errors if the last chunk is swapped', function (t) {
  t.plan(1);
  var data1 = new Buffer(16);
  data1.fill(8);
  var data2 = new Buffer(16);
  data2.fill(4);
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = new Buffer('');
  val.on('data', function (d) {
    out = Buffer.concat([out, d]);
  }).on('end', function () {
    //t.ok(false);
  }).on('error', function (e) {
    t.equals(e.message, 'missing data', 'should error');
  });
  var auterData  = new Buffer('');
  var ended = false;
  auther.on('data', function (d) {
    if(ended === true) {
      return;
    }
    val.write(d);
    if (d.toString('hex') === '04040404040404040404040404040404') {
      ended = true;
      val.end();
    }
    auterData = Buffer.concat([auterData, d]);
  });
  auther.on('end', function () {
    if (!ended){
      val.end(crypto.randomBytes(32));
    }
  });
  auther.write(data1);
  auther.write(data2);
  auther.end();
});
test('errors if the chunks are swaped', function (t) {
  t.plan(2);
  var data1 = new Buffer(16);
  data1.fill(2);
  var data2 = new Buffer(16);
  data2.fill(4);
  var data3 = new Buffer(16);
  data3.fill(6);
  var data4 = new Buffer(16);
  data3.fill(8);
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = new Buffer('');
  var error = false;
  val.on('data', function (d) {
    out = Buffer.concat([out, d]);
  }).on('finish', function () {
    t.equals(out.toString('hex'), data1.toString('hex'), 'did not emit too much');
  }).on('error', function (e) {
    if (!error) {
      error = true;
      t.equals(e.message, 'invalid chunk size', 'should error');
    }
  });
  var auterData  = new Buffer('');
  var ended = false;
  var prev = new Buffer('');
  var swap;
  auther.on('data', function (d) {
    if (d.toString('hex') === '04040404040404040404040404040404') {
      swap = Buffer.concat([prev, d]);
      prev = new Buffer('');
    } else if (d.toString('hex') === '06060606060606060606060606060606') {
      val.write(prev);
      val.write(d);
      val.write(swap);
      prev = new Buffer('');
    } else {
      val.write(prev);
      prev = d;
    }
    auterData = Buffer.concat([auterData, d]);
  });
  auther.on('finish', function () {
    if (!ended){
      val.end();
    }
  });
  auther.write(data1);
  auther.write(data2);
  auther.write(data3);
  auther.write(data3);
  auther.end();
});
test('works with small chunk size', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer(16);
  key.fill(8);
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = '';
  val.on('data', function (d) {
    out += d.toString();
  }).on('end', function () {
    t.ok(auterData.length > 1000, 'correct length');
    t.equals(out, data);
  });
  var auterData = new Buffer('');
  auther.pipe(val);
  auther.on('data', function (d) {
    auterData = Buffer.concat([auterData, d]);
  });
  auther.write(new Buffer(data));
  auther.end();
});

function append(d) {
  d = Buffer.concat([d, new Buffer('abc')]);
  return d;
}
function makeBad(d) {
  d.writeUInt8((d.readUInt8(0) + 1)%256, 0);
  return d;
}
function slice(d) {
  return d.slice(0, -1);
}
manipulateData('increment', makeBad);
manipulateData('append', append);
manipulateData('slice', slice);
function manipulateData(name, trans) {
  test(name, function (t) {
    t.test('bad data', function (t) {
      t.plan(2);
      var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
      var key = new Buffer(16);
      key.fill(8);
      var auther = new auth.Authenticate(key);
      var val = new auth.Verify(key);
      var out = '';
      var error = false;
      val.on('data', function (d) {
      }).on('finish', function () {
        t.ok(true, 'done');
      }).on('error', function (e) {
        if (!error) {
          error = true;
          t.ok(true, 'errored');
        }
      });
      var i = 0;
      auther.on('data', function (d) {
        if (++i === 4) {
          d = trans(d);
        }
        if (error) {
          return;
        }
        val.write(d);
      }).on('finish', function () {
        val.end();
      });
      auther.write(new Buffer(data));
      auther.end();
    });
    t.test('bad chunk size', function (t) {
      t.plan(1);
      var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
      var key = new Buffer(16);
      key.fill(8);
      var auther = new auth.Authenticate(key);
      var val = new auth.Verify(key);
      var out = '';
      var error = false;
      val.on('data', function (d) {
      }).on('error', function (e) {
        if (!error) {
          error = true;
          t.ok(true, 'errored');
        }
      });
      var i = 0;
      auther.on('data', function (d) {
        if (++i === 3) {
          d = trans(d);
        }
        if (error) {
          return;
        }
        val.write(d);
      }).on('end', function () {
        val.end();
      });
      auther.write(new Buffer(data));
      auther.end();
    });
    t.test('bad hash', function (t) {
      t.plan(2);
      var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
      var key = new Buffer(16);
      key.fill(8);
      var auther = new auth.Authenticate(key);
      var val = new auth.Verify(key);
      var out = '';
      var error = false;
      val.on('data', function (d) {
      }).on('finish', function () {
        t.ok(true, 'done');
      }).on('error', function (e) {
        if (!error) {
          error = true;
          t.ok(true, 'errored');
        }
      });
      var i = 0;
      auther.on('data', function (d) {
        if (++i === 2) {
          d = trans(d);
        }
        if (error) {
          return;
        }
        val.write(d);
      }).on('finish', function () {
        val.end();
      });
      auther.write(new Buffer(data));
      auther.end();
    });
  });
}
test('unit', function (t){
  t.test('is different', function (t){
    t.plan(4);
    var a = new Buffer(32);
    var b = new Buffer(32);
    a.fill(8);
    b.fill(8);
    t.notOk(utils.areDifferent(a, b), 'confirm 2 similar ones');
    b[1] = 7;
    t.ok(utils.areDifferent(a, b), 'reject 2 different ones');
    var c = new Buffer(33);
    c.fill(8);
    t.ok(utils.areDifferent(a, c), 'reject incorrect sizes');
    t.ok(utils.areDifferent(c, a), 'reject incorrect sizes');
  });
});