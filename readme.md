hmac-stream[![Build Status](https://travis-ci.org/calvinmetcalf/hmac-stream.svg)](https://travis-ci.org/calvinmetcalf/hmac-stream)
====

A streaming hmac authenticator, the idea being for use in an 'Encrypt-then-MAC' (EtM) approach meaning you want a flow something like.  [Other similar ideas](https://www.imperialviolet.org/2014/06/27/streamingencryption.html).

```js
dataSource.pipe(cipher).pipe(authenticator).pipe(outStream);
//then
inStream.pipe(verifier).pipe(decipher).pipe(doStuff);
```

cipher and decipher can be any cipher stream, the built in node `crypto.createCipheriv` or my module [create-cipher](https://github.com/calvinmetcalf/create-cipher) should work with it.  

This module works to authenticate by:

- Calculating a random salt and emit it
- generate an iv and an end tag using the salt and the supplied password using `crypto.pbkdf2`
- chunk size is treated as additional authenticated data, so an hmac (using the iv) is generated and emitted followed by the chunk size
- the iv is incremented by 1
- for each chunk of data
    - generate and emit header which is
        - 4 bytes which represents the chunk length
        - msb designates it is an end chunk
    - generate and emit hmac for header plus chunk
    - emit data
    - increment iv by 1
- for the last chunk of data
  - generate header with first byte set to 1
  - generate the hmac with hmac(header + data + end tag)
  - emit hmac then data
  - fill the iv and the end tag with zeros

to verify:

- treat the first 32 bytes of the stream as a salt
- use that to calculate iv and end tag
- next 32 bytes is the hmac for the max block size followed by the max block size
- verify the block size and throw an error if it doesn't match
- increment the iv
- for each chunk of data
    - if chunk size is larger then max block size throw error
    - generate and check hmac
    - if it matches
        - emit data
        - increment iv by 1
    - otherwise throw error
- for the last chunk of data
  - generate the hmac with hmac(data + end tag)
  - check the chunk and either emit it or throw an error
  - fill the iv and the end tag with zeros

It should throw errors if
  - any data is modified
  - any data is omitted (even at the end)
  - pieces of data are swapped
  - pieces of data are duplicated

## API

```js
var hmacStream = require('hmac-stream');

createCipher.Authenticate(password, chunksize={max: 4*1024, min: 16});
createCipher.Verify(password);
```

- password: will be passed to `crypto.pbkdf2`
- chunksize: the max and min sizes of chunks, if a number is passed here it is assumed to be the max.
    - max: the max amount of data covered by an hmac, up to this amount of data is cached before the hmac is checked so think of this as the maximum amount of fake data an attacker can waste your time with before you notice. When buffers of larger then this are written to the stream they are chopped up into chunks smaller then the max size.
    - min: the minimum amount of data to wait for until sending a chunk, the hmac and headers add an overhead of 37 bytes per chunk so if data is coming in in drips and drabs then we might want to wait before emitting data. By default set to 16 bytes which is the block size of AES, can be set to 1 to turn off (and should be for use with stream ciphers).


# Versions
- 0.0.0: first version
- 0.1.0: lowered default chunk size.
- 1.0.0: add end tag to guard against the last block being dropped
- 2.0.0: added variable block sizes
