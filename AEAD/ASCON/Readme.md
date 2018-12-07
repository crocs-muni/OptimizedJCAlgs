# ASCON

## Optimizations Used:
 * Much faster bit rotation
 * Removed 8 byte tempbuf
 * Changed method visibility

## Profiling:

### Speed:
Optimized version:
```
.cap file size: 6,302 bytes

Until initialization:           7 ms
initialization:                51 ms
data padding:                   4 ms
populating state:              19 ms
initial permutation:          766 ms
adding key:                     4 ms
process associated data:      404 ms
process plaintext:            781 ms
generate tag:                 790 ms

Total:                       2826 ms
```
Unoptimized version:
```
.cap file size: 6,294 bytes

Until initialization:           8 ms
initialization:                52 ms
data padding:                   2 ms
populating state:               8 ms
initial permutation:         6354 ms
adding key:                     4 ms
process associated data:     3178 ms
process plaintext:           6553 ms
generate tag:                6354 ms

Total:                      22513 ms
```

We went from 22,5 seconds to less than 3 seconds when processing 16 bytes of data. That is almost 8 times faster! Also, some arrays were removed so it takes less RAM space.

### RAM:
Unoptimized version:
```
128 bytes
```
Optimized version:
```
120 bytes
```
128 - 120 = 8 bytes (6,25% smaller)
