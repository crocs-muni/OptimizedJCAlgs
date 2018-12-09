# Password-Based Key Derivation Function 2 (PBKDF2)

## Project Status
- [x] Code is working
- [x] Code is optimized
- [x] Code is beautified
- [x] Usage info is provided
- [x] Example is provided
- [x] Profiling data are collected & interpreted
- [x] Side-channel vulnerability data are collected
- [x] Diploma thesis article is written

## Briefly about PBKDF2
Password-Based Key Derivation Function 2 is exactly how it sounds. You provide a password+salt, and it will spit out a strong cryptographic key.
It iterates as many times as needed (more iterations = more security), computng and xoring HMAC over and over, together with salt.
This implementation offers HMAC_SHA-1 and HMAC_SHA-256, and maximum salt length of 16 bytes.

## Usage
PBKDF2 doesn't extend any other class, because it requires specific inputs, but imitates the usage of MessageDigest.
The constructor is protected, therefore the only way to instantiate PBKDF2 is through the getInstance() method.
### Interface:
Create PBKDF2 instance:
````java
public static PBKDF2 getInstance(byte algorithm) {


algorithm                 // either ALG_SHA or ALG_SHA256
return                    // the instance of PBKDF2
throws NO_SUCH_ALGORITHM  // if input algorithm is different
````
Compute key:
````java
public short doFinal(byte[] password, short passwordOffset, short passwordLength,
                     byte[] salt,     short saltOffset,     short saltLength,
                     short iterations,
                     byte[] out,      short outOffset)

password                  // password to make key from
passwordOffset            // password buffer offset
passwordLength            // password buffer length
salt                      // salt input buffer
saltOffset                // salt input buffer offset
saltLength                // salt input buffer length
iterations                // number of iterations of computation
out                       // output buffer
outOffset                 // output buffer offset
return                    // the length of processed data (length of mesageDigest; 20 for SHA-1, 32 for SHA-256)
throws ILLEGAL_USE        // if saltLength is longer than 16 bytes
````

## Example
Simple example how to create, instantiate and use PBKDF2 in the JavaCard applet:
```` java
// create entities
private   PBKDF2  m_pbkdf2 = null; //password digest

// instantiate the 128-bit cipher and key
m_pbkdf2 = PBKDF2.getInstance(PBKDF2.ALG_SHA);


// create key from password "password" and salt "salt": 
// m_ramArray1 = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64}
// m_ramArray2 = {0x73, 0x61, 0x6C, 0x74}
short ret = m_pbkdf2.doFinal(m_ramArray1, (short) 0, (short) 8, m_ramArray2, (short) 0, (short) 4, (short) 1, m_ramArray3, (short) 0);
````

## Optimizations used
* Removed redundant arrays (RAM saving)
* Minimized number of method parameters (worse readability but faster)
* Code beautification (better readability)
* Added hardware HMAC possibility, which is much faster, but it may not work on all cards

## Performance measurement results
PBKDF2 using HMAC_SHA1 with input data: "password" and "salt", with 512 iterations:
```
invoke doFinal:     0 ms
first HMAC invoke:  7 ms
  if statement:     1 ms
  XOR + arrayCopy: 26 ms
  hash:             3 ms
  copy array:       5 ms
out of hmac:        7 ms

511 hmacs:      23296 ms

one hmac avg:     ~45 ms
```
PBKDF2 using HMAC_SHA256 with same input:
```
512 hmacs:      28350 ms

one hmac avg:     ~55 ms
```
We see that if we wanted to comply with Kerberos' HMAC_SHA256 with 4096 iterations, it would take at least 3 minutes and 47 seconds.
