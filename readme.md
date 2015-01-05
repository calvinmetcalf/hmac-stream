hmac-stream[![Build Status](https://travis-ci.org/calvinmetcalf/hmac-stream.svg)](https://travis-ci.org/calvinmetcalf/hmac-stream)
====

A streaming hmac authenticator, the idea being for use in an 'Encrypt-then-MAC' (EtM) approach meaning you want a flow something like.  [Other similar ideas](https://www.imperialviolet.org/2014/06/27/streamingencryption.html).

```js
var hmacStream = require('hmac-stream')
dataSource.pipe(cipher).pipe(authenticator).pipe(outStream);
//then
inStream.pipe(verifier).pipe(decipher).pipe(doStuff);
```

cipher and decipher can be any stream that needs to be authenticated.

This module creates an :

- append 4 zeros to the key to get the iv
- create an 8 byte block, the first 4 bytes are the aad length, the second 4 bytes are the max chunk size
- create an hmac for the aad and the previous block and emit it
- emit the block
- increment the iv by 1
- for each chunk
    - generate header which is sized depending on the max chunk size such that
        - if max chunk size is 254 or less 1 byte
        - if max chunk size is 65534 or less 2 bytes
        - else 4 bytes
    - write the byte size of the chunk to the header
    - generate and emit an hmac for the header plus chunk based on the current iv
    - emit the header
    - emit the data
    - increment the hmac by 1
- when done
    - create and emit an hmac for a zero length header
    - create and emit a maxed out header (all bytes 0xff)

It should throw errors if
  - any data is modified
  - any data is omitted (even at the end)
  - pieces of data are swapped
  - pieces of data are duplicated
  - the aad is incorect

## API

```js
var hmacStream = require('hmac-stream');

createCipher.Authenticate(key, aad, maxSize);
createCipher.Verify(key, aad);
```

- password: key must be at least 128 bits (16 bytes)
- aad: any additional data to authenticate
- maxSize: maximum size of a chunk, defaults to 4k.


# Versions
- 0.0.0: first version
- 0.1.0: lowered default chunk size.
- 1.0.0: add end tag to guard against the last block being dropped
- 2.0.0: added variable block sizes
- 3.0.0: takes a key instead of a password, supports aad, treats end tags differently.