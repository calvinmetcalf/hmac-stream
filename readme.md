hmac-stream[![Build Status](https://travis-ci.org/calvinmetcalf/hmac-stream.svg)](https://travis-ci.org/calvinmetcalf/hmac-stream)
====

A streaming hmac authenticator, the idea being for use in an 'Encrypt-then-MAC' (EtM) approach meaning you want a flow something like.  [Other similar ideas](https://www.imperialviolet.org/2014/06/27/streamingencryption.html).

```js
var hmacStream = require('hmac-stream')
var authenticator = new hmacStream.Authenticate('key');
var verifier = new hmacStream.Verify('key');
dataSource.pipe(cipher).pipe(authenticator).pipe(outStream);
//then
inStream.pipe(verifier).pipe(decipher).pipe(doStuff);
```

cipher and decipher can be any stream that needs to be authenticated.

procedure:

- take a key, aad, and MAX CHUNK SIZE
    - if aad is undefined default to an empty buffer
    - if key is less then 128 bits (aka 16 bytes) throw an error.
    - if MAX CHUNK SIZE is undefined default it to Infinity
- create an 4 byte block of the aad length as a big endian 32 bit unsigned integers.
- create an hmac for the aad and the previous block and emit it
- increment the key by 1
- for each chunk
    - if chunk is larger then MAX CHUNK SIZE split into chunks of MAX CHUNK SIZE or less
    - generate a header of 4 bytes
    - write the byte size of the chunk to the header
    - generate and emit an hmac for the header
    - emit the header
    - increment the key by 1
    - generate and emit an hmac for the data
    - emit the data
    - increment the key by 1
- when done
    - emit an hmac and header for a chunk of size zero

To verify:


- accept 2 arguments a key and an aad buffer.
    - if key is less then 128 bits (aka 16 bytes) throw an error.
    - if aad is undefined default to an empty buffer.
- accept initial information
    - first 32 bytes of stream will be hmac for aad
    - create hmac of aad, add aad length as 32 bit BE buffer
    - verify against aad received
- then
    - wait for 32 + 4 bytes this is the hmac plus chunk len
    - verify chunk length
      - if verifies set chunk length
      - else throw error
    - if chunk length is zero stream is ended
    - wait for 32 + chunk length
    - verify chunk
      - if verified emit chunk
      - else throw error

It should throw errors if
  - any data is modified
  - any data is omitted (even at the end)
  - pieces of data are swapped
  - pieces of data are duplicated
  - the aad is incorrect

It should allow streaming with no buffering and without an adversary
being able to do a DDOS against you.

## API

```js
var hmacStream = require('hmac-stream');

hmacStream.Authenticate(key, aad, maxSize);
hmacStream.Verify(key, aad);
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
- 4.0.0: chunk length is mac'd separately. 
