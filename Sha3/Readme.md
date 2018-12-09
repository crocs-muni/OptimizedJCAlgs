# Sha3 Keccak

## Project Status
- [x] Code is working
- [ ] SHAKE is implemented (optional)
- [x] Code is optimized
- [x] Code is beautified
- [x] Usage info is provided
- [x] Example is provided
- [x] Profiling data are collected & interpreted
- [x] Side-channel vulnerability data are collected
- [x] Diploma thesis article is written

## Briefly about Sha3
SHA-3 is the new hashing standard approved in 2015. It doesn't serve as a replacement for SHA-2, raher serves as an alternative since it uses quite different computation than SHA-1 and SHA-2 do. It's reasonably fast while providing great security. It also provides Extensible Output Functions that allows users to get output of arbitrary length (not implemented here, yet). 
## Usage
SHA-3 extends the MessageDigest class, therefore you are able to use it the same way you would use any other message digest algorithm.
The constructor is protected, therefore the only way to instantiate Sha3 is through the getInstance() method.
### Interface:
Create SHA-3 instance:
````java
public static Sha3 getInstance(byte algorithm)

algorithm                 // ALG_SHA3_224 or ALG_SHA3_256 or ALG_SHA3_384 or ALG_SHA3_512
return                    // the instance of SHA-3 engine
throws NO_SUCH_ALGORITHM  // if algorithm is unsupported
````
Reset SHA-3 to its initial state:
```` java
public void reset()
````
Sponge absorb data:
```` java
public void update(byte[] inBuff, short inOffset, short inLength)

inBuff                    // input buffer
inOffset                  // input buffer offset
inLength                  // input buffer length
````
Sponge absorb last piece of data and squeeze:
````java
public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {

inBuff                    // input buffer
inOffset                  // input buffer offset
inLength                  // input buffer length
outBuff                   // output buffer
outOffset                 // output buffer offset
return                    // the length of processed data
````
Get SHA-3 algorithm tag:
```` java
public byte getAlgorithm()

return                    // ALG_SHA3_224 or ALG_SHA3_256 or ALG_SHA3_384 or ALG_SHA3_512 (7/8/9/10)
````

Get SHA-3 message digest length:
```` java
public byte getLength()

return                    // 28 or 32 or 48 or 64
````
## Example
````java
//create entity
private   MessageDigest m_sha3 = null;

// instantiate 256-bit algorithm
m_sha3 = Sha3.getInstance(Sha3.ALG_SHA3_256);

// digest 17 bytes of data
short ret1 = m_sha3.doFinal(m_ramArray1, (short) 0, (short) 17, apdubuf, (short) 0);
````
## Optimizations used
* Changed the naive and abnormally slow bitwise operation into a godly superfast one (well, as much as it gets)
* Unrolled several loops
* Got rid of redundant code
* Changed visibility of non-interface methods to package-only or private (safer)
* Minimized number of method parameters (worse readability but faster)
* Beautified code (better readability)
* Created proper MessageDigest interface

## Measurement results

### Speed
Unrolled for loops:
```
init:                       17 ms
swap endian:                16 ms
theta (arrayCopy and XOR):  25 ms
theta (copy, XOR, rotlW):   59 ms
rho+pi (24x rotlW):        112 ms
chi (copy and negate):      96 ms
swap endian:                22 ms
Keccakf (24 rounds):      6746 ms
```
Classic for loops:
```
init:                       18 ms
swap endian:                15 ms
theta (arrayCopy and XOR):  27 ms
theta (copy, XOR, rotlW):   58 ms
rho+pi (24x rotlW):        110 ms
chi (copy and negate):      99 ms
swap endian:                19 ms
Keccakf (24 rounds):      6813 ms 
```
### RAM

```
257 bytes
```
