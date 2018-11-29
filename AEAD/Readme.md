# Authenticated Encryption with Associated Data

This folder contains 5 optimized versions of AEAD algorithms:
* ACORN
* AEGIS
* ASCON
* CLOC
* MORUS

Profiling data of each one is in their respective folder in Readme. All optimizations run faster, some run much more faster, some just very slightly. But they are also less memory-consuming now.

For more info about AEAD on javacard, and its usage, visit original project repository:\
https://github.com/palkrajesh/AEonJC

Some interfaces have been slightly changed. Init now doesn't take all data as input, rather than only needed initialization parameters. All data for encryption/decryption are now taken by encrypt/decrypt methods, which are, together with init, the only public methods.
```
public void init(byte[] nsecret,  byte[] npublic, byte[] key)

public byte encrypt(byte[] cipher,   short cipherlen,
                    byte[] message,  short messagelen,
                    byte[] authdata, short authdatalen)
```
