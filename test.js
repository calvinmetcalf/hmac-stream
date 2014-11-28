var test = require('tape');
var crypto = require('crypto');
var auth = require('./');

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
function getBuffer(len) {
  var b = new Buffer(len);
  b.fill(len);
  return b;
}
test('min size', function (t) {
  t.test('should work', function (t) {
    t.plan(2);
    var key = new Buffer(16);
    key.fill(8);
    var auther = new auth.Authenticate(key);
    var i = 3;
    var out = [];
    auther.on('data', function (d) {
      out.push(d);
    });
    auther.write(getBuffer(8));
    t.equals(out.length, 1, 'nothing in there');
    auther.write(getBuffer(9));
    t.equals(out.length, 6, 'something in there');
  });
  t.test('should be able to turn it off', function (t) {
    t.plan(2);
    var key = new Buffer(16);
    key.fill(8);
    var auther = new auth.Authenticate(key, {min: 1});
    var i = 3;
    var out = [];
    auther.on('data', function (d) {
      out.push(d);
    });
    auther.write(getBuffer(8));
    t.equals(out.length, 6, 'nothing in there');
    auther.write(getBuffer(9));
    t.equals(out.length, 9, 'something in there');
  });
});
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
  val.on('data', function (d) {
    out = Buffer.concat([out, d]);
  }).on('finish', function () {
    t.equals(out.toString('hex'), data1.toString('hex'), 'did not emit too much');
  }).on('error', function (e) {
    t.equals(e.message, 'invalid block size', 'should error');
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
      }).on('end', function () {
        t.ok(true, 'done');
      }).on('error', function (e) {
        error = true;
        t.ok(true, 'errored');
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
      t.plan(2);
      var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
      var key = new Buffer(16);
      key.fill(8);
      var auther = new auth.Authenticate(key);
      var val = new auth.Verify(key);
      var out = '';
      var error = false;
      val.on('data', function (d) {
      }).on('end', function () {
        t.ok(true, 'done');
      }).on('error', function (e) {
        error = true;
        t.ok(true, 'errored');
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
      }).on('finish', function () {
        val.end();
      });
      auther.write(new Buffer(data));
      auther.end();
    });
    t.test('bad salt', function (t) {
      t.plan(2);
      var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
      var key = new Buffer(16);
      key.fill(8);
      var auther = new auth.Authenticate(key);
      var val = new auth.Verify(key);
      var out = '';
      var error = false;
      val.on('data', function (d) {
      }).on('end', function () {
        t.ok(true, 'done');
      }).on('error', function (e) {
        error = true;
        t.ok(true, 'errored');
      });
      var i = 0;
      auther.on('data', function (d) {
        //console.log(i, d.toString('hex'));
        if (++i === 1) {
          d = trans(d);
          //console.log('trans', d.toString('hex'));
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
        error = true;
        t.ok(true, 'errored');
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