hmac-stream[![Build Status](https://travis-ci.org/calvinmetcalf/hmac-stream.svg)](https://travis-ci.org/calvinmetcalf/hmac-stream)
====

a streaming hmac authenticator, the idea being for use in an 'Encrypt-then-MAC' (EtM) approach meaning you want a flow something like

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
    - generate and emit hmac
    - emit data
    - increment iv by 1
- for the last chunk of data
  - generate the hmac with hmac(data + end tag)
  - emit hmac then data
  - fill the iv and the end tag with zeros

to verify:

- treat the first 32 bytes of the stream as a salt
- use that to calculate iv and end tag
- next 32 bytes is the hmac for the block size followed by the block size
- verify the block size and throw an error if it doesn't match
- increment the iv
- for each chunk of data
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

createCipher.Authenticate(password, chunkSize = 512);
createCipher.Verify(password);
```

- password: will be passed to `crypto.pbkdf2`
- chunkSize: the amount of data to cover by one hmac. 

The hmac adds an overhead of 32 bytes per chunk and is always emitted before the chunk, since data will only be emited in chunks of this size it is important to lower this number for streams where throughput speed is more important then size.  As it is set by default you need to write 512 worth of data before it will emit anything (or close the stream), this is a compromise between overhead (default is 6% per chunk) and though put for situations where you are reading a stream quickly in one quick shot (e.g. fs.createReadStream) you may want to increase this but if you have a stream where small bits of data come over a longer period of time you'd want to set this lower, for instance if you had a a tcp stream which gets 50 bytes every minute, then by default you'd get a burst of data every 10 minutes.


# Versions
- 0.0.0: first version
- 0.1.0: lowered default chunk size.
- 1.0.0: add end tag to guard against the last block being dropped
