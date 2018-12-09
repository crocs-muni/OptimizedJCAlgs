# Zorro Cipher

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/7/7b/Attention_Sign.svg/1169px-Attention_Sign.svg.png" alt="Warning! " width="25">  **__BE CAREFUL WHEN USING ZORRO, IT HAS BEEN BROKEN AND IS NOT SECURE__**  <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/7/7b/Attention_Sign.svg/1169px-Attention_Sign.svg.png" alt="Warning! " width="25">\
Read more here: https://eprint.iacr.org/2014/220.pdf

## Project Status
- [x] Code is working
- [x] Code is optimized
- [x] Code is beautified
- [x] Usage info is provided
- [x] Example is provided
- [x] Speed profiling data are collected & interpreted
- [x] Memory profiling data are collected & interpreted
- [x] Side-channel vulnerability data are collected
- [x] Diploma thesis article is written

## Briefly about Zorro
Zorro is a lightweight 128-bit block cipher whose goal is to provide an AES-like encryption on JavaCards
while being able to be masked against side-channel attacks more efficiently.

## Usage
Zorro extends the Cipher class, therefore you are able to use it the same way you would use any other block cipher, such as AES.
The constructor is protected, therefore the only way to instantiate Zorro is through the getInstance() method.
### Interface:
Create ZorroCipher instance:
````java
public static ZorroCipher getInstance()

return                    // the instance of Zorro cipher
````
Initialize ZorroCipher with key for encryption/decryption:
```` java
public void init(Key theKey, byte theMode)

theKey                    // initialized 128-bit AESKey with 128 bits of data
theMode                   // either Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT
throws UNINITIALIZED_KEY  // if theKey wasn't properly initialized yet
throws ILLEGAL_VALUE      // if theKey is not a 128-bit AESKey
````
Encrypt/decrypt supported data:
````java
public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)

inBuff                    // input buffer
inOffset                  // input buffer offset
inLength                  // input buffer length
outBuff                   // output buffer
outOffset                 // output buffer offset
return                    // the length of processed data (same as inLength if properly executed)
throws UNINITIALIZED_KEY  // if cipher wasn't initialized using the init() method.
throws ILLEGAL_VALUE      // if inLength is not a multiple of 16 (because Zorro is NOPAD)
throws INVALID_INIT       // if mode is neither MODE_ENCRYPT nor MODE_DECRYPT
````
Get ZorroCipher algorithm tag:
```` java
public byte getAlgorithm()

return  ALG_ZORRO         // 18
````
Update (not supported):
```` java
public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)

throws ILLEGAL_USE        // always throws this
// this method is not supported on lightweight Zorro cipher (just use doFinal)
````
Initialize with array (not supported)
```` java
public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen)
throws ILLEGAL_USE        // always throws this
// this method is not supported on lightweight Zorro cipher (use supported init)
````

## Example
Simple example how to create, instantiate and use ZorroCipher in the JavaCard applet:
```` java
//create entities
private Cipher m_zorro = null; // cipher
private AESKey m_aes = null;   // key

//instantiate the 128-bit cipher and key
m_zorro = ZorroCipher.getInstance();
m_aes   = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

//init aes key and Zorro cipher for encrpytion
m_aes.setKey(m_ramArray, (short) 0);
m_zorro.init(m_aes, Cipher.MODE_ENCRYPT);

//encrypt 32 bytes of data
short ret = m_zorro.doFinal(m_ramArray1, (short) 0, (short) 32, apdubuf, ISO7816.OFFSET_CDATA);
````

## Optimizations used
* DESKey changed to AESKey (no impact on performance, but is more true to the nature of Zorro)
* Changed visibility of non-interface methods to package-only (safer)
* Temporary variables are now all stored in one array (faster)
* Minimized number of method parameters (worse readability but faster)
* Beautified code (better readability) (not complete)
* Created proper Cipher interface

## Performance measurement results
### Speed
Old Zorro encrypting 16 bytes of data:
```
init:               7 ms

getKey:             2 ms
Encrypt:
  xor key:          4 ms
  mix1Column:      24 ms
  mix4Columns:     89 ms
  1 round:         97 ms
  4 rounds:       389 ms
  24 rounds:     2338 ms

encrypt:         2361 ms
cleanup:          n/a
```
New Zorro encrypting 16 bytes of data:
```
init:               7 ms

getKey:             2 ms
Encrypt:
  xor key:          4 ms
  mix1Column:      22 ms
  mix4Columns:     80 ms
  1 round:         93 ms
  4 rounds:       375 ms
  24 rounds:     2232 ms

encrypt:         2259 ms
cleanup:            4 ms
```
The new - optimized Zorro is about 100 ms faster. This is because of loop unrolling and better handling of arrays. We also added cleanup for safety reasons, which takes only 4 ms therefore is negligible time-wise. Alltogether we report a 4.5% speed increase.

We see that whole encryption takes around 2250 ms. This is split into 6 steps, each containing 4 rounds. Each step lasts 375 ms. Each round lasts 93 ms, split into 4 functions: SubBytes, AddConstant and ShiftRows last together about 13 ms, where MixColumns itself lasts 80 ms. In MixColumns, there are 4 identical steps, each lasting about 20-22 ms. Each step is 16 multiplications over Galois field (mGF). Each multiplication is over 1 ms long. Since we perform ``16 x 4 x 4 x 6 = 1546`` multiplications, the computation can't last less than that many milliseconds. All other computations also take some time (although that's only a small portion), resulting in an average 2250 ms long computation. So mGF is what takes so long and cannot be further optimized.

### Memory

```
40 bytes
```
Zorro only needs 40 bytes to save the state. Nothing more.
