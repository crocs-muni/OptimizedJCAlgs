package applets;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.CryptoException;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;


/**
 *
 * @author Matej Evin
 * 03 August 2018
 */

// This is the simplified version of PBKDF2 on JavaCard. It does not support any other hash functions than Sha1 and Sha256.
// This is pretty much optimized for speed, but still it is a very lengthy process, because it requires a lot of iterations
// on a slow CPU with very limited memory.
//
// If you know of any speed/memory optimizations, please let me know, I'll surely acknowledge you in my diploma thesis.
// This one uses software implementation of HMAC. There is also hardware (faster) implementation, but it may not work
 
//////////////
//   TODO   //
//////////////
 
// optimize memory usage - draw a diagram of array access, and figure out if some arrays can't be merged (because now we require a lot of RAM)
 
public class PBKDF2 {
  
    //Public Defines (copied from MessageDigest source code)
    public static final byte  ALG_SHA            = 1;
    public static final byte  ALG_SHA_256        = 4;
    public static final byte  LENGTH_SHA         = 20;
    public static final byte  LENGTH_SHA_256     = 32;
    public static final short BLOCKSIZE_SHA      = 64;
    
    private final static short SALT_LEN          = 16; //maximum usable length of salt (bytes)
    
    //macros
    private final static short  SZERO           = (short) 0x0;
    private final static byte   BZERO           = (byte)  0x0;
    private final static byte   BONE            = (byte)  0x01;
    
    //variables
    private static short mdlen;                                 //message digest length
    
    //variable arrays
    private byte[] U_i                          = null;         //intermediate values of F function
    private byte[] keyprime                     = null;         //place to store K' for creating HMAC
    private byte[] innerblock                   = null;         //place to store inner block of HMAC
    private byte[] outerblock                   = null;         //place to store outer block of HMAC
    
    //engines
    private         MessageDigest   m_hash      = null;         //hash engine
    private static  PBKDF2          m_instance  = null;         //instance of pbkdf2 itself
    //private         HMACKey         m_key       = null;         //HMAC Key structure
    //private         Signature       m_hmac      = null;         //HMAC Signature engine
    
    //constructor called during card installation. Nothing really to do here
    protected PBKDF2() {}

    //get PBKDF2Core Instance
    //what happens if there is already an instance and I try to get a different one?
    public static PBKDF2 getInstance(byte algorithm) throws CryptoException {
        if (m_instance == null)
        {
            m_instance = new PBKDF2();
            
            switch(algorithm) {
                case ALG_SHA:
                    m_instance.m_hash = MessageDigest.getInstance(ALG_SHA, false);
                    //m_instance.m_hmac = Signature.getInstance(Signature.ALG_HMAC_SHA1, false);
                    //m_instance.m_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_1_BLOCK_64, false);
                    PBKDF2.mdlen  = LENGTH_SHA;
                    break;
                case ALG_SHA_256:
                    m_instance.m_hash = MessageDigest.getInstance(ALG_SHA_256, false);
                    //m_instance.m_hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
                    //m_instance.m_key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
                    PBKDF2.mdlen  = LENGTH_SHA_256;
                    break;
                default:
                    throw new CryptoException(CryptoException.NO_SUCH_ALGORITHM);
            }
        
            //prepare space for saving hash results
            //is it better to create arrays all at the start, or create them on the fly?
            //for SHA256 - 288 bytes of transient memory
            m_instance.U_i        = JCSystem.makeTransientByteArray(mdlen, JCSystem.CLEAR_ON_DESELECT);                          //32 bytes  //resulting hmac
            m_instance.keyprime   = JCSystem.makeTransientByteArray(BLOCKSIZE_SHA, JCSystem.CLEAR_ON_DESELECT);                  //64 bytes  //padded/hashed key for HMAC
            m_instance.innerblock = JCSystem.makeTransientByteArray((short)(BLOCKSIZE_SHA + mdlen), JCSystem.CLEAR_ON_DESELECT); //96 bytes  //create enough space for hash
            m_instance.outerblock = JCSystem.makeTransientByteArray((short)(BLOCKSIZE_SHA + mdlen), JCSystem.CLEAR_ON_DESELECT); //96 bytes  //create enough space for hash
        }
        return m_instance;
    }
    
    //K - Key, offset, length
    //mLength - length of salt (U_i, offset 0)
    //output into U_i, return length of output
    //out array may overlap K or m arrays.
    private short hmac(byte[] K, short KOffset, short KLength, short mLength) {
         
        //if short key, needs padding with zeros
        if (KLength < BLOCKSIZE_SHA) {
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
        Util.arrayCopyNonAtomic(U_i, SZERO, innerblock, BLOCKSIZE_SHA, mLength);
        m_hash.doFinal(innerblock, SZERO, (short) (BLOCKSIZE_SHA+mLength), innerblock, SZERO);
        
        //concatenate and digest outer part, save HMAC and return its length
        Util.arrayCopyNonAtomic(innerblock, SZERO, outerblock, BLOCKSIZE_SHA, mdlen);
        return m_hash.doFinal(outerblock, SZERO, (short) (BLOCKSIZE_SHA+mdlen), U_i, SZERO);
    }
    
    //pw - input password
    //salt - input salt
    //iterations - # of runs
    //out - output array
    //return length of output
    public short doFinal(byte[] password, short passwordOffset, short passwordLength,
                         byte[] salt, short saltOffset, short saltLength,
                         short iterations,
                         byte[] out, short outOffset) throws CryptoException {
        
        if (SALT_LEN < saltLength)
            throw new CryptoException(CryptoException.ILLEGAL_USE);
        
        //concatenate with int32BE(1) (salt is max 16, U_i is at least 20, so 4 more bytes can always fit there)
        Util.arrayCopyNonAtomic(salt, saltOffset, U_i, SZERO, saltLength);
        U_i[         saltLength     ] = BZERO;
        U_i[(short) (saltLength + 1)] = BZERO;
        U_i[(short) (saltLength + 2)] = BZERO;
        U_i[(short) (saltLength + 3)] = BONE;
        
        //generate first HMAC
        //hardware HMAC - uncomment these 3 lines and comment the next line to swap HW/SW computation
        //m_key.setKey(password, passwordOffset, passwordLength);
        //m_hmac.init(m_key, Signature.MODE_SIGN);
        //m_hmac.sign(U_i, SZERO, (short) (saltLength + 4), U_i, SZERO);
        //software HMAC
        hmac(password, passwordOffset, passwordLength, (short) (saltLength + 4));
        //insert U_1 into result array
        Util.arrayCopyNonAtomic(U_i, SZERO, out, outOffset, mdlen);
        //do the rest of iterations. We already did first iteration above, that's why we start at 1
        for (short k = 1; k < iterations; k++) {
            //Same with HMAC here
            //m_hmac.sign(U_i, SZERO, mdlen, U_i, SZERO);  // Hardware hmac
            hmac(password, passwordOffset, passwordLength, mdlen);          // Software hmac
            //xor U_(i-1) with U_i
            for (short j = 0; j < mdlen; j++) {
                out[(short) (outOffset + j)] ^= U_i[j];
            }
        }
        
        return mdlen;
    }
}
