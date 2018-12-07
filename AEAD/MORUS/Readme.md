# MORUS

## Optimizations Used:
 * removed redundant variables and temporaries
 * reduced method visibility to package only
 * inlined many function calls
 * improved byte shifting
 * moved many parts to init
 * unrolled many loops
 
## Profiling:

### Speed (16 byte input 0x00 - 0x0f):
Optimized version:
```
.cap file size: 10,347 bytes

Until initialization:           8 ms
initialization:              2286 ms
endianness changes:           263 ms
process associated data:       80 ms
process plaintext:            140 ms
generate tag:                 781 ms

Total:                       3558 ms

(255 bytes are encrypted in 6270 ms)
```
Unoptimized version:
```
.cap file size: 8,534 bytes

Until initialization:           8 ms
initialization:             53827 ms
endianness changes:           466 ms
process associated data:     3333 ms
process plaintext:           3341 ms
generate tag:               26768 ms

Total:                      87743 ms
```
We cut the computation time from 87,7 seconds to 3,5 seconds. That is more than 24x faster!\
We also moved most of the code to initialization, so subsequent runs of encrypt() would take only about 1,3 seconds.\
Improved bitshifts and byte shifts are the main reason of this speedup.\
The only price for this is cap being bigger by 1500 bytes, which is is completely negligible in this case.

### RAM:
```
128 bytes
```
```
128 bytes
```
No improvement
