# OptimizedJCAlgs
Collection of open-source JavaCard crypto algorithms. Optimized for memory and speed with unified interface

### List of known JC crypto algs on GitHub:
* Elliptic curves: [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib)
* Sha3 (Keccak+SHAKE): [JCSha3](https://github.com/MiragePV/JCSha3) (I'll probably discard this one. It needs A LOT of work)
* [JCSWAlgs](https://github.com/JavaCardSpot-dev/JCSWAlgs)
  * Sha3
  * Sha512
  * AES
  * Twine Cipher
  * Zorro Cipher
* [Primitives_SmartCard](https://github.com/albertocarp/Primitives_SmartCard/tree/master/src/sid)
  * Sha3
  * LBlock Cipher
  * Picollo Cipher
  * Rectangle Cipher
* Authenticated Encryption: [AEonJC](https://github.com/palkrajesh/AEonJC)
  * AEGIS
  * ACORN
  * ASCON
  * CLOC
  * MORUS
* [OpenPGP](https://github.com/jderuiter/javacard-openpgpcard) - open source PGP on JC
* [LedgerHQ Wallet](https://github.com/LedgerHQ/ledger-javacard) - implementation of Ledger cryptocurrency wallet on JC

Profiling and optimization tools:
* [JCProfiler](https://github.com/OpenCryptoProject/JCProfiler)
* [MemoryMeasurement](https://github.com/maxashwin/JavaCard/tree/master/Wkg_MemoryMeasurementScript)
* [JCAlgTest](https://github.com/crocs-muni/JCAlgTest)

JC miracle doer: [Martin Paljak](https://github.com/martinpaljak)
* [JC-ant](https://github.com/martinpaljak/ant-javacard#syntax)
* [Global Platform Pro](https://github.com/martinpaljak/GlobalPlatformPro)
* [Applet Playground](https://github.com/martinpaljak/AppletPlayground)

### What should the card provide?

* Ciphers:
  * RSA (nopad, PKCS1, ISO9796, OAEP)
  * AES (CBC128, ECB128, CBC256, ECB256, nopad, ISO9797, PKCS5)
  * DES (CBC, ECB, nopad, PKCS5, ISO9797)
  * ECC
  * (some others?)
* Signature schemes:
  * RSA
  * DSA 
  * ECDSA
* Message digests (hashes):
  * SHA2 (256, 384, 512)
  * SHA3 (224, 256, 384, 512)
  * MD5
* On-card Key-pair generation (maybe?)
* Authenticated encryption with associated data (AEAD)
