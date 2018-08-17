package applets;

import javacard.framework.*;
import javacard.security.*;


/**
 *
 * @author Matej Evin
 * 03 August 2018
 */
public class PBKDF2Core {
  
    //Public Defines (copied from MessageDigest source code)
    public static final byte  ALG_SHA            = 1;
    public static final byte  ALG_SHA_256        = 4;
    public static final byte  ALG_SHA_384        = 5;
    public static final byte  ALG_SHA_512        = 6;
    public static final byte  LENGTH_SHA         = 20;
    public static final byte  LENGTH_SHA_256     = 32;
    public static final byte  LENGTH_SHA_384     = 48;
    public static final byte  LENGTH_SHA_512     = 64;
    public static final short BLOCKSIZE_SHA      = 64;
    public static final short BLOCKSIZE_SHA_256  = 64;
    public static final short BLOCKSIZE_SHA_384  = 128;
    public static final short BLOCKSIZE_SHA_512  = 128;
    
    //Private defines
    private final static byte  SUCCESS          = 0;
    
    private final static short SALT_LEN         = 16; //maximum usable length of salt (bytes)
    
    //macros
    private final static short  SZERO           = (short) 0x0;
    private final static byte   BZERO           = (byte)  0x0;
    private final static byte   BONE            = (byte)  0x01;
    
    //variables
    private short mdlen;                                        //message digest length
    private short blocksize;                                    //message digest block size
    
    //variable arrays
    private byte[] U_i                          = null;         //intermediate values of F function
    //private byte[] Fresult                      = null;         //xored U_i's
    private byte[] concatSalt                   = null;         //salt concatenated with i
    private byte[] keyprime                     = null;         //place to store K' for creating HMAC
    private byte[] innerblock                   = null;         //place to store inner block of HMAC
    private byte[] outerblock                   = null;         //place to store outer block of HMAC
    
    //engines
    private     MessageDigest   m_hash          = null;         // hash of primary session key
    
    //constructor called during card installation. Nothing really to do here
    public PBKDF2Core(){}

    //initialisation with arbitrary hash function
    //algorithm - check public defines. Onty sha1, sha256 and sha512 are implemented (so far)
    public byte getInstance(byte algorithm) {
        switch(algorithm) {
            case ALG_SHA:
                m_hash = MessageDigest.getInstance(ALG_SHA, false);
                mdlen = LENGTH_SHA;
                blocksize = BLOCKSIZE_SHA;
                break;
            case ALG_SHA_256:
                m_hash = MessageDigest.getInstance(ALG_SHA_256, false);
                mdlen = LENGTH_SHA_256;
                blocksize = BLOCKSIZE_SHA_256;
                break;
            case ALG_SHA_384:
                m_hash = MessageDigest.getInstance(ALG_SHA_384, false);
                mdlen = LENGTH_SHA_384;
                blocksize = BLOCKSIZE_SHA_384;
                break;
            case ALG_SHA_512:
                m_hash = MessageDigest.getInstance(ALG_SHA_512, false);
                mdlen = LENGTH_SHA_512;
                blocksize = BLOCKSIZE_SHA_512;
                break;
            default:
                return CryptoException.NO_SUCH_ALGORITHM;    
        }
        
        //prepare space for saving hash results
        U_i        = JCSystem.makeTransientByteArray(mdlen, JCSystem.CLEAR_ON_DESELECT); //resulting hmac
        concatSalt = JCSystem.makeTransientByteArray((short)(SALT_LEN + 4), JCSystem.CLEAR_ON_DESELECT); //salt to use in U_i. 16 byte salt + 4 bytes of possible INT_32_BE(i)
        keyprime   = JCSystem.makeTransientByteArray(blocksize, JCSystem.CLEAR_ON_DESELECT); // padded/hashed key for HMAC
        innerblock = JCSystem.makeTransientByteArray((short)(blocksize + mdlen), JCSystem.CLEAR_ON_DESELECT); // create enough space for hash
        outerblock = JCSystem.makeTransientByteArray((short)(blocksize + mdlen), JCSystem.CLEAR_ON_DESELECT); // create enough space for hash
        
        return SUCCESS;
    }
    
    //doFinal (maybe rename it later?)
    //pw - input password
    //salt - input salt
    //iterations - # of runs
    //out - output array
    public short doFinal(byte[] password, short passwordOffset, short passwordLength,
                         byte[] salt, short saltOffset, short saltLength,
                         short iterations,
                         byte[] out, short outOffset, short outLength) {
        
        //insert DKlen handling here, don't forget to change all iterative elements properly!
        //might not be implemented at all
        //for now, we test if output is at most the same length as initialized digest length (therefore only T_1 is needed)
        if (mdlen < outLength) return CryptoException.ILLEGAL_VALUE;
        
        //copy salf to larger array. Salt must be max SALT_LEN (16 bytes for now)
        if (SALT_LEN < saltLength) return CryptoException.ILLEGAL_USE;
        Util.arrayCopyNonAtomic(salt, saltOffset, concatSalt, SZERO, saltLength);
        
        //concatenate with int32BE(i)
        concatSalt[         saltLength     ] = BZERO;
        concatSalt[(short) (saltLength + 1)] = BZERO;
        concatSalt[(short) (saltLength + 2)] = BZERO;
        concatSalt[(short) (saltLength + 3)] = BONE;  // TODO CHANGE THIS VALUE TO i LATER!!!!
        
        //generate first HMAC
        hmac(password, passwordOffset, passwordLength, concatSalt, SZERO, (short) (saltLength + 4), U_i, SZERO);
        //insert U_1 into Fresult
        //TODO outOFFSET SHOULD BE EVEN MORE OFFSETED FOR EACH T_i
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
        if (KLength < blocksize) { //if short key, needs padding with zeros
            Util.arrayFillNonAtomic(keyprime, SZERO, blocksize, BZERO); // fill array with zeros
            Util.arrayCopyNonAtomic(K, KOffset, keyprime, SZERO, KLength); // copy Key inside
        }
        if (KLength > blocksize) { // if long key, needs hashing
            m_hash.doFinal(K, KOffset, KLength, keyprime, SZERO);
        }
        //xor with ipad/opad
        for (short i = 0; i < blocksize; i++) {
            innerblock[i] = (byte) (keyprime[i] ^ ((byte) 0x36));
            outerblock[i] = (byte) (keyprime[i] ^ ((byte) 0x5c));
        }
        
        //concatenate and digest inner part
        Util.arrayCopyNonAtomic(m, SZERO, innerblock, blocksize, mLength);
        short ret = m_hash.doFinal(innerblock, SZERO, (short) (blocksize+mLength), innerblock, SZERO);
        
         //concatenate and digest outer part, save HMAC and return its length
        Util.arrayCopyNonAtomic(innerblock, SZERO, outerblock, blocksize, mdlen);
        return m_hash.doFinal(outerblock, SZERO, (short) (blocksize+mdlen), out, outOffset);
    }
    
}

