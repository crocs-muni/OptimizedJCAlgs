Encryption process profiling data (decryption is the very similar):\
Optimized version:
```
Until initialization:           7 ms
initialization:             18989 ms
encryption preparation:        35 ms
process associated data 1:   3306 ms
process associated data 2:  12191 ms
process plaintext 1:         3374 ms
process plaintext 2:        12178 ms
generate tag:               12119 ms
finalize encryption:            6 ms
```
