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

- take a key, aad, and a MAX CHUNK SIZE
    - if MAX CHUNK SIZE is undefined default to 4k
    - if aad is undefined default to an empty buffer
    - if key is less then 128 bits (aka 16 bytes) throw an error.
- create an 8 byte block, the first 4 bytes are the aad length, the second 4 bytes
    are the MAX CHUNK SIZE encoded as big endian 32 bit unsigned integers. 
- create an hmac for the aad and the previous block and emit it
- emit the block
- increment the key by 1
- for each chunk
    - if chunk is larger then MAX CHUNK SIZE split into chunks of MAX CHUNK SIZE or less
    - generate header which is sized depending on the MAX CHUNK SIZE such that
        - if MAX CHUNK SIZE is 254 or less 1 byte
        - if MAX CHUNK SIZE is 65534 or less 2 bytes
        - else 4 bytes
    - write the byte size of the chunk to the header
    - generate and emit an hmac for the header plus chunk based on the current iv
    - emit the header
    - emit the data
    - increment the hmac by 1
- when done
    - emit an hmac and header for a chunk of size zero

To verify:


- accept 2 arguments a key and an aad buffer.
    - if key is less then 128 bits (aka 16 bytes) throw an error.
    - if aad is undefined default to an empty buffer.
- accept initial information
    - first 16 bytes of stream will be hmac for aad and chunk size
    - next 4 bytes will be MAX CHUNK SIZE
    - create hmac of aad, add aad length as 32 bit BE buffer, add 4 byte MAX CHUNK SIZE
    - verify against aad received
    - set MAX CHUNK SIZE
    - set HEADER SIZE based on MAX CHUNK SIZE
- then
    - wait for 32 bytes this is the hmac
    - wait for HEADER SIZE number of bytes
    - read header
        - if header contains a length greater then MAX CHUNK SIZE, throw error.
        - if header contains a length of zero then verify against hmac
            - if it verifies then end stream
            - if not throw error
        - else set this as CHUNK SIZE
        - increment key
    - wait for CHUNK SIZE number of bytes
        - create hmac of chunk size and chunk then verify
            - if it verifies emit chunk
            - if not throw error
        - increment key

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