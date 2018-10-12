# TWINE Cipher

## Briefly about Twine
Twine is a lightweight block cipher which utilises a 4x4 substitution box and a 144byte RoundKey (state). Whether you use an 80-bit or 128-bit key, it gets expanded using the substitution box into a RoundKey of the constant 144-byte length. The longer key adds more entropy to the expansion procedure and therefore more entropy to the encryption and decryption itself.

## Usage
Twine extends the Cipher class, therefore you are able to use it the same way you would use any other block cipher, such as AES.
The constructor is protected, therefore the only way to instantiate Twine is through the getInstance() method.
### Interface:
```
public static TwineCipher getInstance(byte algorithm)
algorithm  either TWINE_CIPHER_80 or TWINE_CIPHER_128
return     the instance of Twine cipher```
```
```
public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
inBuff     input buffer
inOffset   input buffer offset
inLength   input buffer length
outBuff    output buffer
outOffset  output buffer offset
return     the length of processed data (same as inLength if properly executed)
throws     UNINITIALIZED_KEY if cipher wasn't initialized using init() method.
throws     ILLEGAL_USE if inLength is not a multiple of 8 (NOPAD)
```

```
public void init(Key theKey, byte theMode)
theKey   initialized 128bit DESKey with either 80bits or 128bits of data
theMode  either Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT
throws   UNITIALIZED_KEY if theKey wasn't properly initialized yet
throws   ILLEGAL_VALUE if theKey is not a 128bit DESKey
```

```
public byte getAlgorithm()
return  ALG_TWINE value
```

```
public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
always throws INVALID_INIT exception
this method is not supported on lightweight Twine cipher (just use doFinal)
```

```
public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen)
always throws INVALID_INIT exception
this method is not supported on lightweight Twine cipher (use supported init)
```

## Example

## Optimizations used
