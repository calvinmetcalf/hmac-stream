var test = require('tape');

var auth = require('./');

test('works', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer('calvin');
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
test('works with small chunk size', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer('calvin');
  var auther = new auth.Authenticate(key, 16);
  var val = new auth.Verify(key);
  var out = '';
  val.on('data', function (d) {
    out += d.toString();
  }).on('finish', function () {
    t.ok(auterData.length > 1000, 'correct length');
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
test('bad data', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer('calvin');
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
    if (++i === 4) {
      d.writeUInt8((d.readUInt8(0) + 1)%256, 0);
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
test('bad chunk size', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer('calvin');
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
    if (++i === 3) {
      d.writeUInt8((d.readUInt8(0) + 1)%256, 0);
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
test('bad salt', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer('calvin');
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
    if (++i === 1) {
      d.writeUInt8((d.readUInt8(0) + 1)%256, 0);
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
test('bad hash', function (t) {
  t.plan(2);
  var data = 'If you consent, neither you nor any other human being shall ever see us again; I will go to the vast wilds of South America.  My food is not that of man; I do not destroy the lamb and the kid to glut my appetite; acorns and berries afford me sufficient nourishment.  My companion will be of the same nature as myself and will be content with the same fare. We shall make our bed of dried leaves; the sun will shine on us as on man and will ripen our food.  The picture I present to you is peaceful and human, and you must feel that you could deny it only in the wantonness of power and cruelty.  Pitiless as you have been towards me, I now see compassion in your eyes; let me seize the favourable moment and persuade you to promise what I so ardently desire.';
  var key = new Buffer('calvin');
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
      d.writeUInt8((d.readUInt8(0) + 1)%256, 0);
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