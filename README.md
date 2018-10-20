# OptimizedJCAlgs
Collection of open-source JavaCard crypto algorithms. Optimized for memory and speed with unified interface

### List of known JC crypto algs on GitHub:
* Elliptic curves: [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib)
* Sha3 (Keccak): [JCSha3](https://github.com/MiragePV/JCSha3), [OptimizedJCAlgs](https://github.com/MiragePV/OptimizedJCAlgs) (Discontinued on JCSha3, continuing here; SHAKE not done yet)
* [JCSWAlgs](https://github.com/JavaCardSpot-dev/JCSWAlgs) (don't blindly trust the code there)
  * Sha3
  * Sha512
  * AES
  * Twine Cipher (incorrect implementation there, correct here)
  * Zorro Cipher (correct implementation here, needs more review though)
* [Primitives_SmartCard](https://github.com/albertocarp/Primitives_SmartCard/tree/master/src/sid)
  * Sha3
  * LBlock Cipher
  * Picollo Cipher
  * Rectangle Cipher
* Authenticated Encryption: [AEonJC](https://github.com/palkrajesh/AEonJC) (well optimized)
  * AEGIS (
  * ACORN
  * ASCON (optimization improvement: 435%: from 135seconds to 31 seconds!)
  * CLOC
  * MORUS
* [OpenPGP](https://github.com/jderuiter/javacard-openpgpcard) - open source PGP on JC
* [LedgerHQ Wallet](https://github.com/LedgerHQ/ledger-javacard) - implementation of Ledger cryptocurrency wallet on JC
* Password-based key derivation: [OptimizedJCAlgs](https://github.com/MiragePV/OptimizedJCAlgs) - this project, unoptimized (yet)
  * PBKDF2 (Sha1, Sha256; single-block, 128-bit salt) (pretty slow)

Profiling and optimization tools:
* [JCProfiler](https://github.com/OpenCryptoProject/JCProfiler)
* [MemoryMeasurement](https://github.com/maxashwin/JavaCard/tree/master/Wkg_MemoryMeasurementScript)
* [JCAlgTest](https://github.com/crocs-muni/JCAlgTest)

JC miracle people: [Martin Paljak](https://github.com/martinpaljak), [PetrS](https://github.com/petrs)
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
* Password-Based Key Derivation (PBKDF2) - done in this project
* Authenticated encryption with associated data (AEAD)


### Profiling and optimizing
#### JCSha3
~300 % faster (28.5s to 9s)
JCProfiler trace:
```
[PERF_START-TRAP_keccakf_1],            99 ms   - initializing
[TRAP_keccakf_1-TRAP_keccakf_2], 	18 ms   - handling endianness (could be optimized out probably)
[TRAP_keccakf_2-TRAP_keccakf_3], 	27 ms   - array assignments
[TRAP_keccakf_3-TRAP_keccakf_4], 	45 ms   - theta function
[TRAP_keccakf_4-TRAP_keccakf_5], 	204 ms  - rho & pi functions (bitwise rotation is longest part)
[TRAP_keccakf_5-TRAP_keccakf_6], 	107 ms  - chi function
[TRAP_keccakf_6-TRAP_keccakf_7], 	0 ms    - iota function (just an assignment so it takes little time)
[TRAP_keccakf_7-TRAP_keccakf_8], 	8814 ms - 24 rounds of keccak (24x trap3-7)
[TRAP_keccakf_8-TRAP_keccakf_9], 	31 ms   - handling endianness
[TRAP_keccakf_9-TRAP_keccakf_COMPLETE], 19 ms   - finalizing hash algorithm
```
Removing endianness could cut some more time, more rotation optimizations are still possible, cutting up to 60 % of its computation time.

#### Twine Cipher
no comparison to original - original was unfinished and not working correctly\
averages of NetBeans profiler traces of Twine128:
```
[Twine_init_80],  204 ms - initializing with 80-bit key
[Twine_init_128], 337 ms - initializing with 128-bit key
[8_byte_enc],     362 ms - encryption of 8 bytes
[8_byte_enc],     371 ms - encryption of 8 bytes
[Twine_cleanup],    4 ms - clearing memory after use
```
With 128-bit key we are averaging 1070ms on encrypting/decrypting 16 bytes of data (ECB mode)\
CAP file is 6.6kb in size.
