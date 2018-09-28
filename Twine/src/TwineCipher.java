package applets;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 * The TWINE Cipher implementation
 *
 * @author Alberto-PC
 * @optimized Matej Evin 27.9.2018
 */

 public class TwineCipher extends Cipher {

    //TWINE-specific tables
    private final byte[] ROUNDCONST = {
        (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x03, (byte) 0x06, (byte) 0x0c,
        (byte) 0x18, (byte) 0x30, (byte) 0x23, (byte) 0x05, (byte) 0x0a, (byte) 0x14, (byte) 0x28, (byte) 0x13, (byte) 0x26,
        (byte) 0x0f, (byte) 0x1e, (byte) 0x3c, (byte) 0x3b, (byte) 0x35, (byte) 0x29, (byte) 0x11, (byte) 0x22, (byte) 0x07,
        (byte) 0x0e, (byte) 0x1c, (byte) 0x38, (byte) 0x33, (byte) 0x25, (byte) 0x09, (byte) 0x12, (byte) 0x24, (byte) 0x0b
    };

    private final short[] SHUF = {
        (short) 5, (short) 0, (short) 1, (short) 4, (short) 7, (short) 12, (short) 3, (short) 8,
        (short) 13, (short) 6, (short) 9, (short) 2, (short) 15, (short) 10, (short) 11, (short) 14
    };

    private final short[] SHUFINV = {
        (short) 1, (short) 2, (short) 11, (short) 6, (short) 3, (short) 0, (short) 9, (short) 4,
        (short) 7, (short) 10, (short) 13, (short) 14, (short) 5, (short) 8, (short) 15, (short) 12
    };

    private final byte[] SBOX = {
        (byte) 0x0C, (byte) 0x00, (byte) 0x0F, (byte) 0x0A, (byte) 0x02, (byte) 0x0B, (byte) 0x09, (byte) 0x05,
        (byte) 0x08, (byte) 0x03, (byte) 0x0D, (byte) 0x07, (byte) 0x01, (byte) 0x0E, (byte) 0x06, (byte) 0x04
    };

    //constants
    public static final short TEMP_LENGTH       = 32;
    public static final short TEMP_HALF         = 16;
    public static final short RK_LENGTH         = 288;
    public static final byte  ALG_TWINE         = 19;
    public static final byte  TWINE_CIPHER_80   = 0x30;
    public static final byte  TWINE_CIPHER_128  = 0x31;

    //Key storage (make it AES?)
    private DESKey cipherKey;

    //variables
    private byte               mode;                        //mode - encrypt/decrypt
    private static short       keyLength;                   //length of key in bits (80 or 128)
    private static TwineCipher m_instance       = null;     //instance of cipher
    private boolean            isInitialized    = false;    //flag if engine is initialized with key

    //ram arrays
    public byte[] temp  = JCSystem.makeTransientByteArray(TEMP_LENGTH, JCSystem.CLEAR_ON_DESELECT); // temporary - for intermediate values
    public byte[] rk    = JCSystem.makeTransientByteArray(RK_LENGTH, JCSystem.CLEAR_ON_DESELECT);     // round key - takes 288 bytes yet uses just 4 bits of each byte. Can be maybe optimized, but needs more complicated mathematic operations

    //expand key, called by init function
    //expand key takes second half of temp array where key is stored temporarily
    private void expand80Key() {
        short i;

        //this double typecasting looks so bad. there must be a better way
        //needs testing
        temp[0]  = (byte) ((short) (temp[16] & 0x00FF) >> 4);
        temp[1]  = (byte) ((short) (temp[16] & 0x00FF) & 0x0F);
        temp[2]  = (byte) ((short) (temp[17] & 0x00FF) >> 4);
        temp[3]  = (byte) ((short) (temp[17] & 0x00FF) & 0x0F);
        temp[4]  = (byte) ((short) (temp[18] & 0x00FF) >> 4);
        temp[5]  = (byte) ((short) (temp[18] & 0x00FF) & 0x0F);
        temp[6]  = (byte) ((short) (temp[19] & 0x00FF) >> 4);
        temp[7]  = (byte) ((short) (temp[19] & 0x00FF) & 0x0F);
        temp[8]  = (byte) ((short) (temp[20] & 0x00FF) >> 4);
        temp[9]  = (byte) ((short) (temp[20] & 0x00FF) & 0x0F);
        temp[10] = (byte) ((short) (temp[21] & 0x00FF) >> 4);
        temp[11] = (byte) ((short) (temp[21] & 0x00FF) & 0x0F);
        temp[12] = (byte) ((short) (temp[22] & 0x00FF) >> 4);
        temp[13] = (byte) ((short) (temp[22] & 0x00FF) & 0x0F);
        temp[14] = (byte) ((short) (temp[23] & 0x00FF) >> 4);
        temp[15] = (byte) ((short) (temp[23] & 0x00FF) & 0x0F);
        temp[16] = (byte) ((short) (temp[24] & 0x00FF) >> 4);
        temp[17] = (byte) ((short) (temp[24] & 0x00FF) & 0x0F);
        temp[18] = (byte) ((short) (temp[25] & 0x00FF) >> 4);
        temp[19] = (byte) ((short) (temp[25] & 0x00FF) & 0x0F);

        for (i = 0; i < 35; i++) {
            rk[(short) (i * 8)] = temp[1];
            rk[(short) (i * 8 + 1)] = temp[3];
            rk[(short) (i * 8 + 2)] = temp[4];
            rk[(short) (i * 8 + 3)] = temp[6];
            rk[(short) (i * 8 + 4)] = temp[13];
            rk[(short) (i * 8 + 5)] = temp[14];
            rk[(short) (i * 8 + 6)] = temp[15];
            rk[(short) (i * 8 + 7)] = temp[16];

            temp[1] ^= SBOX[temp[0]];
            temp[4] ^= SBOX[temp[16]];
            temp[7] ^= ROUNDCONST[i] >> 3;
            temp[19] ^= ROUNDCONST[i] & 7;

            //ROTL4 of first 4 elements
            temp[20] = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = temp[20];
            
            //ROTL16 of all 20 elements
            temp[20] = temp[0];   temp[21] = temp[1];   temp[22] = temp[2];   temp[23] = temp[3];
            temp[0]  = temp[4];   temp[1]  = temp[5];   temp[2]  = temp[6];   temp[3]  = temp[7];
            temp[4]  = temp[8];   temp[5]  = temp[9];   temp[6]  = temp[10];  temp[7]  = temp[11];
            temp[8]  = temp[12];  temp[9]  = temp[13];  temp[10] = temp[14];  temp[11] = temp[15];
            temp[12] = temp[16];  temp[13] = temp[17];  temp[14] = temp[18];  temp[15] = temp[19];
            temp[16] = temp[20];  temp[17] = temp[21];  temp[18] = temp[22];  temp[19] = temp[23];
        }

        rk[280] = temp[1];
        rk[281] = temp[3];
        rk[282] = temp[4];
        rk[283] = temp[6];
        rk[284] = temp[13];
        rk[285] = temp[14];
        rk[286] = temp[15];
        rk[287] = temp[16];
    }

    //todo
    //expand 128bit key
    private void expand128Key() {
        short i;

        //this double typecasting looks so bad. there must be a better way
        //needs testing
        temp[0]  = (byte) ((short) (temp[16] & 0x00FF) >> 4);
        temp[1]  = (byte) ((short) (temp[16] & 0x00FF) & 0x0F);
        temp[2]  = (byte) ((short) (temp[17] & 0x00FF) >> 4);
        temp[3]  = (byte) ((short) (temp[17] & 0x00FF) & 0x0F);
        temp[4]  = (byte) ((short) (temp[18] & 0x00FF) >> 4);
        temp[5]  = (byte) ((short) (temp[18] & 0x00FF) & 0x0F);
        temp[6]  = (byte) ((short) (temp[19] & 0x00FF) >> 4);
        temp[7]  = (byte) ((short) (temp[19] & 0x00FF) & 0x0F);
        temp[8]  = (byte) ((short) (temp[20] & 0x00FF) >> 4);
        temp[9]  = (byte) ((short) (temp[20] & 0x00FF) & 0x0F);
        temp[10] = (byte) ((short) (temp[21] & 0x00FF) >> 4);
        temp[11] = (byte) ((short) (temp[21] & 0x00FF) & 0x0F);
        temp[12] = (byte) ((short) (temp[22] & 0x00FF) >> 4);
        temp[13] = (byte) ((short) (temp[22] & 0x00FF) & 0x0F);
        temp[14] = (byte) ((short) (temp[23] & 0x00FF) >> 4);
        temp[15] = (byte) ((short) (temp[23] & 0x00FF) & 0x0F);
        temp[16] = (byte) ((short) (temp[24] & 0x00FF) >> 4);
        temp[17] = (byte) ((short) (temp[24] & 0x00FF) & 0x0F);
        temp[18] = (byte) ((short) (temp[25] & 0x00FF) >> 4);
        temp[19] = (byte) ((short) (temp[25] & 0x00FF) & 0x0F);

        for (i = 0; i < 35; i++) {
            rk[(short) (i * 8)] = temp[1];
            rk[(short) (i * 8 + 1)] = temp[3];
            rk[(short) (i * 8 + 2)] = temp[4];
            rk[(short) (i * 8 + 3)] = temp[6];
            rk[(short) (i * 8 + 4)] = temp[13];
            rk[(short) (i * 8 + 5)] = temp[14];
            rk[(short) (i * 8 + 6)] = temp[15];
            rk[(short) (i * 8 + 7)] = temp[16];

            temp[1] ^= SBOX[temp[0]];
            temp[4] ^= SBOX[temp[16]];
            temp[7] ^= ROUNDCONST[i] >> 3;
            temp[19] ^= ROUNDCONST[i] & 7;

            //ROTL4 of first 4 elements
            temp[20] = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = temp[20];
            
            //ROTL16 of all 20 elements
            temp[20] = temp[0];   temp[21] = temp[1];   temp[22] = temp[2];   temp[23] = temp[3];
            temp[0]  = temp[4];   temp[1]  = temp[5];   temp[2]  = temp[6];   temp[3]  = temp[7];
            temp[4]  = temp[8];   temp[5]  = temp[9];   temp[6]  = temp[10];  temp[7]  = temp[11];
            temp[8]  = temp[12];  temp[9]  = temp[13];  temp[10] = temp[14];  temp[11] = temp[15];
            temp[12] = temp[16];  temp[13] = temp[17];  temp[14] = temp[18];  temp[15] = temp[19];
            temp[16] = temp[20];  temp[17] = temp[21];  temp[18] = temp[22];  temp[19] = temp[23];
        }

        rk[280] = temp[1];
        rk[281] = temp[3];
        rk[282] = temp[4];
        rk[283] = temp[6];
        rk[284] = temp[13];
        rk[285] = temp[14];
        rk[286] = temp[15];
        rk[287] = temp[16];
    }
    }

    //encrypt 8 bytes
    private byte encrypt(byte[] src, short srcOff, byte[] dest, short destOff) {

        short i, j;

        //expand plaintext
        //temp[0] - temp[15] now contains plaintext split into 16 4-bit parts 0000xxxx
        temp[0]  = (byte) ((short) (src[(short) (    srcOff)] & 0x00FF) >> 4);
        temp[1]  = (byte) ((short) (src[(short) (    srcOff)] & 0x00FF) & 0x0F);
        temp[2]  = (byte) ((short) (src[(short) (1 + srcOff)] & 0x00FF) >> 4);
        temp[3]  = (byte) ((short) (src[(short) (1 + srcOff)] & 0x00FF) & 0x0F);
        temp[4]  = (byte) ((short) (src[(short) (2 + srcOff)] & 0x00FF) >> 4);
        temp[5]  = (byte) ((short) (src[(short) (2 + srcOff)] & 0x00FF) & 0x0F);
        temp[6]  = (byte) ((short) (src[(short) (3 + srcOff)] & 0x00FF) >> 4);
        temp[7]  = (byte) ((short) (src[(short) (3 + srcOff)] & 0x00FF) & 0x0F);
        temp[8]  = (byte) ((short) (src[(short) (4 + srcOff)] & 0x00FF) >> 4);
        temp[9]  = (byte) ((short) (src[(short) (4 + srcOff)] & 0x00FF) & 0x0F);
        temp[10] = (byte) ((short) (src[(short) (5 + srcOff)] & 0x00FF) >> 4);
        temp[11] = (byte) ((short) (src[(short) (5 + srcOff)] & 0x00FF) & 0x0F);
        temp[12] = (byte) ((short) (src[(short) (6 + srcOff)] & 0x00FF) >> 4);
        temp[13] = (byte) ((short) (src[(short) (6 + srcOff)] & 0x00FF) & 0x0F);
        temp[14] = (byte) ((short) (src[(short) (7 + srcOff)] & 0x00FF) >> 4);
        temp[15] = (byte) ((short) (src[(short) (7 + srcOff)] & 0x00FF) & 0x0F);

        for (i = 0; i < 35; i++) {
            for (j = 0; j < 8; j++) {
                temp[(short) (2 * j + 1)] ^= SBOX[temp[(short) (2 * j)] ^ rk[(short) (i * 8 + j)]];
            }
            for (j = 0; j < 16; j++) {
                temp[(short) (SHUF[j] + TEMP_HALF)] = temp[j];
            }

            Util.arrayCopy(temp, TEMP_HALF, temp, (short) 0, TEMP_HALF);
        }
        //36th sub-block
        for (j = 0; j < 8; j++) {
            temp[(short) (2 * j + 1)] ^= SBOX[temp[(short) (2 * j)] ^ rk[(short) (280 + j)]];
        }

        //result in dest array
        dest[(short) (    destOff)] = (byte) ((temp[0]  << 4) | temp[1]);
        dest[(short) (1 + destOff)] = (byte) ((temp[2]  << 4) | temp[3]);
        dest[(short) (2 + destOff)] = (byte) ((temp[4]  << 4) | temp[5]);
        dest[(short) (3 + destOff)] = (byte) ((temp[6]  << 4) | temp[7]);
        dest[(short) (4 + destOff)] = (byte) ((temp[8]  << 4) | temp[9]);
        dest[(short) (5 + destOff)] = (byte) ((temp[10] << 4) | temp[11]);
        dest[(short) (6 + destOff)] = (byte) ((temp[12] << 4) | temp[13]);
        dest[(short) (7 + destOff)] = (byte) ((temp[14] << 4) | temp[15]);

        return 8; //length of output
    }

    //decrypt 8 bytes
    private byte decrypt(byte[] src, short srcOff, byte[] dest, short destOff) {

        short i, j;

        //expand plaintext
        temp[0]  = (byte) ((short) (src[(short) (    srcOff)] & 0x00FF) >> 4);
        temp[1]  = (byte) ((short) (src[(short) (    srcOff)] & 0x00FF) & 0x0F);
        temp[2]  = (byte) ((short) (src[(short) (1 + srcOff)] & 0x00FF) >> 4);
        temp[3]  = (byte) ((short) (src[(short) (1 + srcOff)] & 0x00FF) & 0x0F);
        temp[4]  = (byte) ((short) (src[(short) (2 + srcOff)] & 0x00FF) >> 4);
        temp[5]  = (byte) ((short) (src[(short) (2 + srcOff)] & 0x00FF) & 0x0F);
        temp[6]  = (byte) ((short) (src[(short) (3 + srcOff)] & 0x00FF) >> 4);
        temp[7]  = (byte) ((short) (src[(short) (3 + srcOff)] & 0x00FF) & 0x0F);
        temp[8]  = (byte) ((short) (src[(short) (4 + srcOff)] & 0x00FF) >> 4);
        temp[9]  = (byte) ((short) (src[(short) (4 + srcOff)] & 0x00FF) & 0x0F);
        temp[10] = (byte) ((short) (src[(short) (5 + srcOff)] & 0x00FF) >> 4);
        temp[11] = (byte) ((short) (src[(short) (5 + srcOff)] & 0x00FF) & 0x0F);
        temp[12] = (byte) ((short) (src[(short) (6 + srcOff)] & 0x00FF) >> 4);
        temp[13] = (byte) ((short) (src[(short) (6 + srcOff)] & 0x00FF) & 0x0F);
        temp[14] = (byte) ((short) (src[(short) (7 + srcOff)] & 0x00FF) >> 4);
        temp[15] = (byte) ((short) (src[(short) (7 + srcOff)] & 0x00FF) & 0x0F);

        for (i = 35; i > 0; i--) {
            for (j = 0; j < 8; j++) {
                temp[(short) (2 * j + 1)] ^= SBOX[temp[(short) (2 * j)] ^ rk[(short) (i * 8 + j)]];
            }

            for (j = 0; j < 16; j++) {
                temp[(short) (SHUFINV[j] + TEMP_HALF)] = temp[j];
            }
            Util.arrayCopy(temp, TEMP_HALF, temp, (short) 0, TEMP_HALF);
        }
        //0th sub-block
        for (j = 0; j < 8; j++) {
            temp[(short) (2 * j + 1)] ^= SBOX[temp[(short) (2 * j)] ^ rk[j]];
        }

        //result in dest array
        dest[(short) (    destOff)] = (byte) ((temp[0]  << 4) | temp[1]);
        dest[(short) (1 + destOff)] = (byte) ((temp[2]  << 4) | temp[3]);
        dest[(short) (2 + destOff)] = (byte) ((temp[4]  << 4) | temp[5]);
        dest[(short) (3 + destOff)] = (byte) ((temp[6]  << 4) | temp[7]);
        dest[(short) (4 + destOff)] = (byte) ((temp[8]  << 4) | temp[9]);
        dest[(short) (5 + destOff)] = (byte) ((temp[10] << 4) | temp[11]);
        dest[(short) (6 + destOff)] = (byte) ((temp[12] << 4) | temp[13]);
        dest[(short) (7 + destOff)] = (byte) ((temp[14] << 4) | temp[15]);

        return 8;
    }

    // START OF INTERFACE //
    
    protected TwineCipher() {
    }

    //this should be here only if we have 1 keySize. If we can't implement 128bit key, this should be the only getInstance method
    //if we implement the 128bit key, this method should be deleted
    public static TwineCipher getInstance(byte algorithm) throws CryptoException {
        switch(algorithm){
            case TWINE_CIPHER_80:
                keyLength = (byte) 80;
                break;
            case TWINE_CIPHER_128:
                keyLength = (byte) 128;
                break;
            default:
                throw new CryptoException(CryptoException.NO_SUCH_ALGORITHM);
        }
        if (m_instance == null) {
            m_instance = new TwineCipher();
        }
        return m_instance;
    }

    @Override
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
            throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
        }
        //not sure how long input this should process. 8 or 16 or how many?
        if (inLength % 8 != 0) {
            throw new CryptoException(CryptoException.ILLEGAL_USE);
        }

        short i;
        if (mode == Cipher.MODE_ENCRYPT) {
            for (i = 0; i < inLength / 8; i++) {
                encrypt(inBuff, (short) (i * 8 + inOffset), outBuff, (short) (i * 8 + outOffset));
            }
            Util.arrayFillNonAtomic(temp, (short) 0, TEMP_LENGTH, (byte) 0);
        } else {
            for (i = 0; i < inLength / 8; i++) {
                decrypt(inBuff, (short) (i * 8 + inOffset), outBuff, (short) (i * 8 + outOffset));
            }
            Util.arrayFillNonAtomic(temp, (short) 0, TEMP_LENGTH, (byte) 0);
        }
        return inLength;
    }

    @Override
    public void init(Key theKey, byte theMode) throws CryptoException {
        if (!theKey.isInitialized()) {
            throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
        }

        //DESKey is always 128 bit
        if (theKey.getSize() != 128 || theKey.getType() != KeyBuilder.TYPE_DES) {
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        }

        mode = theMode;
        cipherKey = (DESKey) theKey;

        //extract the key itself, store temporarily in second half of temp array
        cipherKey.getKey(temp, TEMP_HALF);
        //expand round key with deskey, wipe the key from memory
        switch (keyLength) {
            case (byte) 80:
                expand80Key();
                Util.arrayFillNonAtomic(temp, (short) 0, TEMP_LENGTH, (byte) 0);
                break;
            case (byte) 128:
                expand128Key();
                Util.arrayFillNonAtomic(temp, (short) 0, TEMP_LENGTH, (byte) 0);
                break;
        }

        isInitialized = true;
    }

    @Override
    public byte getAlgorithm() {
        return ALG_TWINE;
    }

    @Override
    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        throw new CryptoException(CryptoException.INVALID_INIT);
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        throw new CryptoException(CryptoException.INVALID_INIT);
    }

    //  END OF INTERFACE  //
}
