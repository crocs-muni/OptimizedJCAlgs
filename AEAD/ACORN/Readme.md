# ACORN

## Optimizations Used:
 * simplified byte shifts
 * removed redundant arrays
 * removed tempbuf
 * inlined functions
 * unrolled some loops
 * removed 1536 bytes of EEPROM
 * removed 1536 writes into EEPROM (this is huge)
 * changed visibility

## Profiling:\
Optimized version:
```
.cap file size: 5,927 bytes

Until initialization:           7 ms
initialization:             18989 ms
encryption preparation:        35 ms
process associated data 1:   3306 ms
process associated data 2:  12191 ms
process plaintext 1:         3374 ms
process plaintext 2:        12178 ms
generate tag:               12119 ms
finalize encryption:            6 ms

Total:                      62205 ms
```
Unoptimized version:
```
.cap file size: 6,005 bytes

Until initialization:           8 ms
initialization:             20688 ms
process associated data 1:   3099 ms
process associated data 2:  12522 ms
process plaintext 1:         3457 ms
process plaintext 2:        12482 ms
generate tag:               12426 ms
finalize encryption:            2 ms

Total:                      64649 ms
```
Speed gain is roughly 4%. Memory footprint, however, is much smaller for optimized version. We cut 1536 bytes of EEPROM and several RAM arrays. Capsize is slightly smaller too.
