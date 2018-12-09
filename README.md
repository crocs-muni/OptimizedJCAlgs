# OptimizedJCAlgs
Collection of open-source JavaCard crypto algorithms. Optimized for memory and speed with unified interface (where possible).
See each algorithm's own readme file for more details.

### Featured algorithms:
* AEGIS, ACORN, ASCON, CLOC, MORUS - Authenticated Encryption
* TWINE, Zorro - Block Ciphers
* SHA-3 - Message Digest
* PBKDF2 - Key derivation
* OpenPGP - extend your GnuPG with smart card!

### List of known JC crypto algs on GitHub:
* Elliptic curves: [JCMathLib](https://github.com/OpenCryptoProject/JCMathLib)
* Sha3 (Keccak): [JCSha3](https://github.com/MiragePV/JCSha3), [OptimizedJCAlgs](https://github.com/MiragePV/OptimizedJCAlgs) (Discontinued on JCSha3, continuing here; SHAKE not done yet)
* [JCSWAlgs](https://github.com/JavaCardSpot-dev/JCSWAlgs) (don't blindly trust the code there)
  * Sha3
  * Sha512
  * AES
  * Twine Cipher (incorrect implementation there, correct here)
  * Zorro Cipher (correct implementation here, but the alg. design is not secure!)
* [Primitives_SmartCard](https://github.com/albertocarp/Primitives_SmartCard/tree/master/src/sid)
  * Sha3
  * LBlock Cipher
  * Picollo Cipher
  * Rectangle Cipher
* Authenticated Encryption: [AEonJC](https://github.com/palkrajesh/AEonJC) (well optimized)
  * AEGIS
  * ACORN
  * ASCON
  * CLOC
  * MORUS
* [OpenPGP](https://github.com/jderuiter/javacard-openpgpcard) - open source PGP on JC
* [LedgerHQ Wallet](https://github.com/LedgerHQ/ledger-javacard) - implementation of Ledger cryptocurrency wallet on JC
* Password-based key derivation: [OptimizedJCAlgs](https://github.com/MiragePV/OptimizedJCAlgs)
  * PBKDF2 (Sha1, Sha256; single-block, 128-bit salt) (pretty slow)

Profiling and optimization tools:
* [JCProfiler](https://github.com/OpenCryptoProject/JCProfiler)
* [MemoryMeasurement](https://github.com/maxashwin/JavaCard/tree/master/Wkg_MemoryMeasurementScript)
* [JCAlgTest](https://github.com/crocs-muni/JCAlgTest)

JC miracle people: [Martin Paljak](https://github.com/martinpaljak), [PetrS](https://github.com/petrs)
* [JC-ant](https://github.com/martinpaljak/ant-javacard#syntax)
* [Global Platform Pro](https://github.com/martinpaljak/GlobalPlatformPro)
* [Applet Playground](https://github.com/martinpaljak/AppletPlayground)
