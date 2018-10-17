# Zorro Cipher

## Project Status
- [ ] Code is working
- [x] Code is optimized
- [x] Code is beautified
- [x] Usage info is provided
- [x] Example is provided
- [ ] Profiling data are collected & interpreted
- [ ] Side-channel vulnerability data are collected
- [ ] Diploma thesis article is written

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
* TODO

## Performance measurement results
