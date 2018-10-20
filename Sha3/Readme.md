# Sha3 Keccak

## Project Status
- [x] Code is working
- [ ] SHAKE is implemented (optional)
- [ ] Code is optimized
- [x] Code is beautified
- [ ] Usage info is provided
- [ ] Example is provided
- [ ] Profiling data are collected & interpreted
- [ ] Side-channel vulnerability data are collected
- [ ] Diploma thesis article is written

## Briefly about Sha3

## Usage
Sha3 extends the MessageDigest class, therefore you are able to use it the same way you would use any other message digest algorithm.
The constructor is protected, therefore the only way to instantiate Sha3 is through the getInstance() method.
### Interface:

## Example

## Optimizations used
* Changed the naive and abnormally slow bitwise operation into a godly superfast one (well, as far as it gets)
* Unrolled several loops
* Got rid of redundant code
* Changed visibility of non-interface methods to package-only or private (safer)
* Minimized number of method parameters (worse readability but faster)
* Beautified code (better readability) (not complete)
* Created proper MessageDigest interface

## Performance measurement results

## Possible further optimizations
* Inline some functions
* Rewrite code so that we don't have to swap endianess
* cast to short when XOR, AND, NOT to compute those operations twice as fast
