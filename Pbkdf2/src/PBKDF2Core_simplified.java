package applets;

import javacard.framework.*;
import javacard.security.*;


/**
 *
 * @author Matej Evin
 * 03 August 2018
 */

// This is the simplified version of PBKDF2 on JavaCard. It does not support any other hash functions than Sha1 and Sha256.
// It does not support outputs longer than hash outputs (sha1 - 20 bytes, sha256 - 32 bytes). But obviously it can be used
// several times and the result then concatenated, which is exactly what extended pbkdf2 does.
// This is pretty much optimized for speed, but still it is a very lengthy process, because it requires a lot of iterations
// on a slow CPU with very limited memory.
//
// Usage: Either use original PBKDF2Core.java, or remove the original and rename this to PBKDF2Core.java.
// There should be only 2 files in the src/ folder - the Core and an example Applet.
//
// If you know of any speed/memory optimizations, please let me know, I'll surely acknowledge you in my diploma thesis.
 
 //////////////
 //   TODO   //
 //////////////
 
 //is it better to create arrays all at the start, or create them on the fly?
 //getInstance method isn't following good coding practices, it should return PBKDF2Core structure, not a byte
 
public class PBKDF2Core {
  
    //Public Defines (copied from MessageDigest source code)
    public static final byte  ALG_SHA            = 1;
    public static final byte  ALG_SHA_256        = 4;
    public static final byte  LENGTH_SHA         = 20;
    public static final byte  LENGTH_SHA_256     = 32;
    public static final short BLOCKSIZE_SHA      = 64;
    public static final short BLOCKSIZE_SHA_256  = 64;
    
    //Private defines
    private final static byte  SUCCESS          = 0;
    
    private final static short SALT_LEN         = 16; //maximum usable length of salt (bytes)
    
    //macros
    private final static short  SZERO           = (short) 0x0;
    private final static byte   BZERO           = (byte)  0x0;
    private final static byte   BONE            = (byte)  0x01;
    
    //variables
    private short mdlen;                                        //message digest length
    
    //variable arrays
    private byte[] U_i                          = null;         //intermediate values of F function
    private byte[] concatSalt                   = null;         //salt concatenated with i
    private byte[] keyprime                     = null;         //place to store K' for creating HMAC
    private byte[] innerblock                   = null;         //place to store inner block of HMAC
    private byte[] outerblock                   = null;         //place to store outer block of HMAC
    
    //engines
    private     MessageDigest   m_hash          = null;         // hash of primary session key
    
    //constructor called during card installation. Nothing really to do here
    public PBKDF2Core(){}

    //instatiation with arbitrary hash function
    //getInstance shouldn't return a byte but the PBKDF2Core object itself,
    //so the initialization looks like this:
    //pbkdf2 = PBKDF2Core.getInstance(ALG_SHA);
    //and not like this:
    //pbkdf2.getInstance(ALG_SHA);
    //but it may be not that important. But it follows the good coding practices and conventions
    //or just don't make it getInstance, but rather an init method (more viable imo)
    public byte getInstance(byte algorithm) {
        switch(algorithm) {
            case ALG_SHA:
                m_hash = MessageDigest.getInstance(ALG_SHA, false);
                mdlen = LENGTH_SHA;
                break;
            case ALG_SHA_256:
                m_hash = MessageDigest.getInstance(ALG_SHA_256, false);
                mdlen = LENGTH_SHA_256;
                break;
            default:
                return CryptoException.NO_SUCH_ALGORITHM;    
        }
        
        //prepare space for saving hash results
        //is it better to create arrays all at the start, or create them on the fly?
        U_i        = JCSystem.makeTransientByteArray(mdlen, JCSystem.CLEAR_ON_DESELECT); //resulting hmac
        concatSalt = JCSystem.makeTransientByteArray((short)(SALT_LEN + 4), JCSystem.CLEAR_ON_DESELECT); //salt to use in U_i. 16 byte salt + 4 bytes of possible INT_32_BE(i)
        keyprime   = JCSystem.makeTransientByteArray(BLOCKSIZE_SHA, JCSystem.CLEAR_ON_DESELECT); // padded/hashed key for HMAC
        innerblock = JCSystem.makeTransientByteArray((short)(BLOCKSIZE_SHA + mdlen), JCSystem.CLEAR_ON_DESELECT); // create enough space for hash
        outerblock = JCSystem.makeTransientByteArray((short)(BLOCKSIZE_SHA + mdlen), JCSystem.CLEAR_ON_DESELECT); // create enough space for hash
        
        return SUCCESS;
    }
    
    //doFinal (maybe rename it later?)
    //pw - input password
    //salt - input salt
    //iterations - # of runs
    //out - output array
    //return length of byte array computed
    public short doFinal(byte[] password, short passwordOffset, short passwordLength,
                         byte[] salt, short saltOffset, short saltLength,
                         short iterations,
                         byte[] out, short outOffset) {
        
        //copy salf to larger array. Salt must be max SALT_LEN (16 bytes for now)
        if (SALT_LEN < saltLength) return CryptoException.ILLEGAL_USE;
        Util.arrayCopyNonAtomic(salt, saltOffset, concatSalt, SZERO, saltLength);
        
        //concatenate with int32BE(i)
        concatSalt[         saltLength     ] = BZERO;
        concatSalt[(short) (saltLength + 1)] = BZERO;
        concatSalt[(short) (saltLength + 2)] = BZERO;
        concatSalt[(short) (saltLength + 3)] = BONE;
        
        //generate first HMAC
        hmac(password, passwordOffset, passwordLength, concatSalt, SZERO, (short) (saltLength + 4), U_i, SZERO);
        //insert U_1 into result array
        Util.arrayCopyNonAtomic(U_i, SZERO, out, outOffset, mdlen);
        //do the rest of iterations. We already did first iteration above, that's why we start at 1
        for (short k = 1; k < iterations; k++) {
            hmac(password, passwordOffset, passwordLength, U_i, SZERO, mdlen, U_i, SZERO);
            //xor U_(i-1) with U_i
            for (short j = 0; j < mdlen; j++) {
                out[(short) (outOffset + j)] ^= U_i[j];
            }
        }
        
        return mdlen; //should be different when concatenating into longer derived key
    }
    
    //K - Key
    //m - message
    //out - output
    //out array may overlap K or m arrays.
    public short hmac(byte[] K, short KOffset, short KLength,
                      byte[] m, short mOffset, short mLength,
                      byte[] out, short outOffset) {
        if (KLength < BLOCKSIZE_SHA) { //if short key, needs padding with zeros
            Util.arrayFillNonAtomic(keyprime, KLength, (short)(BLOCKSIZE_SHA-KLength), BZERO); // fill rest of array with zeros
            Util.arrayCopyNonAtomic(K, KOffset, keyprime, SZERO, KLength); // copy the Key inside
        } else
        if (KLength > BLOCKSIZE_SHA) { // if long key, needs hashing
            m_hash.doFinal(K, KOffset, KLength, keyprime, SZERO);
        } else {
            Util.arrayCopyNonAtomic(K, KOffset, keyprime, SZERO, KLength); // just copy the Key inside
        }
        //xor with ipad/opad
        for (short i = 0; i < BLOCKSIZE_SHA; i++) {
            innerblock[i] = (byte) (keyprime[i] ^ ((byte) 0x36));
            outerblock[i] = (byte) (keyprime[i] ^ ((byte) 0x5c));
        }
        
        //concatenate and digest inner part
        Util.arrayCopyNonAtomic(m, SZERO, innerblock, BLOCKSIZE_SHA, mLength);
        short ret = m_hash.doFinal(innerblock, SZERO, (short) (BLOCKSIZE_SHA+mLength), innerblock, SZERO);
        
         //concatenate and digest outer part, save HMAC and return its length
        Util.arrayCopyNonAtomic(innerblock, SZERO, outerblock, BLOCKSIZE_SHA, mdlen);
        return m_hash.doFinal(outerblock, SZERO, (short) (BLOCKSIZE_SHA+mdlen), out, outOffset);
    }
    
}

