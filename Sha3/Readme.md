# Sha3 Keccak

## Project Status
- [x] Code is working
- [ ] SHAKE is implemented (optional)
- [ ] Code is optimized
- [x] Code is beautified
- [ ] Usage info is provided
- [ ] Example is provided
- [ ] Profiling data are collected & interpreted
- [ ] Side-channel vulnerability data are collected
- [x] Diploma thesis article is written

## Briefly about Sha3

## Usage
Sha3 extends the MessageDigest class, therefore you are able to use it the same way you would use any other message digest algorithm.
The constructor is protected, therefore the only way to instantiate Sha3 is through the getInstance() method.
### Interface:
# TWINE Cipher

## Project Status
- [x] Code is working
- [x] Code is optimized
- [x] Code is beautified
- [x] Usage info is provided
- [x] Example is provided
- [ ] Profiling data are collected & interpreted
- [ ] Side-channel vulnerability data are collected
- [x] Diploma thesis article is written

## Briefly about Twine
Twine is a lightweight block cipher which utilises a 4x4 substitution box and a 144byte RoundKey (state). Whether you use an 80-bit or 128-bit key, it gets expanded using the substitution box into a RoundKey of the constant 144-byte length. The longer key adds more entropy to the expansion procedure and therefore more entropy to the encryption and decryption itself.
## Usage
Twine extends the Cipher class, therefore you are able to use it the same way you would use any other block cipher, such as AES.
The constructor is protected, therefore the only way to instantiate Twine is through the getInstance() method.
### Interface:
Create TwineCipher instance:
````java
public static Sha3Core getInstance(byte algorithm)

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
m_sha3 = Sha3Core.getInstance(Sha3Core.ALG_SHA3_256);

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

## Performance measurement results

## Possible further optimizations
* Inline some functions
* Rewrite code so that we don't have to swap endianess
* cast to short when XOR, AND, NOT to compute those operations twice as fast
