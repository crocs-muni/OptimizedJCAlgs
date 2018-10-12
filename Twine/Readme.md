=TWINE Cipher=

Briefly about Twine
Twine is a lightweight block cipher which utilises a 4x4 substitution box and a 144byte RoundKey (state).
Whether you use an 80-bit or 128-bit key, it gets expanded using the substitution box into a RoundKey of the constant 144-byte length.
The longer key adds more entropy to the expansion procedure and therefore more entropy to the encryption and decryption itself.

Usage
Twine extends the Cipher class, therefore you are able to use it the same way you would use any other block cipher, such as AES.
The constructor is protected, therefore the only way to instantiate Twine is through the getInstance() method.
Interface:
```public static TwineCipher getInstance(byte algorithm) throws CryptoException```
`algorithm` is either TWINE_CIPHER_80 or TWINE_CIPHER_128
`returns` the instance of Twine cipher

public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException
inBuff is input buffer
inOffset is input buffer offset
inLength is input buffer length
outBuff is output buffer
outOffset is output buffer offset
returns the length of processed data (same as inLength if properly executed)
throws UNINITIALIZED_KEY if cipher wasn't initialized using init() method.
throws ILLEGAL_USE if inLength is not a multiple of 8, since this implementation of Twine doesn't pad the input.

public void init(Key theKey, byte theMode) throws CryptoException
theKey is a 128bit DESKey, but can be populated with either 80bits or 128bits of data
theMode is either Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT
you can call init() method again to change the mode or the key whenever you need.

public byte getAlgorithm()
returns ALG_TWINE value, which is 19, but it is an arbitrary number unused by other cipher algorithms.

public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException
always throws INVALID_INIT exception
this method is not supported on lightweight Twine cipher (just use doFinal)

public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException
always throws INVALID_INIT exception
this method is not supported on lightweight Twine cipher (just use )

```

Example

Optimizations used ()
