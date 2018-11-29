# CLOC

## Optimizations Used:
 * removed redundant ram arrays
 * removed redundant variables
 * removed unused decryptCipher
 * inlined some function calls
 * removed software AES implementation
 * moved functionality to init instead of encrypt/decrypt

## Profiling:
 Optimized version:
```
.cap file size: 7,351 bytes

Until initialization:           8 ms
initialization:                 8 ms
process associated data:       38 ms
encrypt plaintext:             30 ms

Total:                         84 ms
```
Unoptimized version:
```
.cap file size: 7,600 bytes

Until initialization:           8 ms
initialization:                19 ms
process associated data:       42 ms
encrypt plaintext:             30 ms

Total:                         99 ms
```
Since CLOC uses internal AES, it is very fast. Our optimizations managed to slightly improve the speed, also improved the code logic by putting more operations into init.
