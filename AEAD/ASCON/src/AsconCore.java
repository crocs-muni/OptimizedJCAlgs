package ascon;

import javacard.framework.*;

/**
 *
 * @author Rajesh Kumar Pal
 * 15 Oct 2017
 * @review Matej Evin
 * 28 Nov 2018
 * 
 * Optimizations used:
 * Faster bit rotation
 * Removed 8 byte tempbuf
 * Changed method visibility
 */

public class AsconCore {
    
    // Defines
    public final static short CRYPTO_KEYBYTES   = 16;
    public final static short CRYPTO_NSECBYTES  = 0;
    public final static short CRYPTO_NPUBBYTES  = 16;
    public final static short CRYPTO_ABYTES     = 16;
    public final static short CRYPTO_NOOVERLAP  = 1;
    public final static short EIGHT             = 8;
    public final static short FORTY             = 40;
    
    
    // Bitwise rotation masks
    final static byte[] ROT_MASK1 = {
        (byte) 0x00, (byte) 0x80, (byte) 0xC0, (byte) 0xE0, (byte) 0xF0, (byte) 0xF8, (byte) 0xFC, (byte) 0xFE};
    
    final static byte[] ROT_MASK2 = {
        (byte) 0x00, (byte) 0x01, (byte) 0x03, (byte) 0x07, (byte) 0x0F, (byte) 0x1F, (byte) 0x3F, (byte) 0x7F};
    
    private byte[] x0 = null;
    private byte[] x1 = null;
    private byte[] x2 = null;
    private byte[] x3 = null;
    private byte[] x4 = null;
    private byte[] t0 = null;
    private byte[] t1 = null;
    private byte[] t2 = null;
    private byte[] t3 = null;
    private byte[] t4 = null;
    private byte[] S = null;
    
    public AsconCore(){
        x0 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x1 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x2 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x3 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        x4 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        
        t0 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t1 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t2 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t3 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        t4 = JCSystem.makeTransientByteArray(EIGHT, JCSystem.CLEAR_ON_DESELECT);
        
        S = JCSystem.makeTransientByteArray(FORTY, JCSystem.CLEAR_ON_DESELECT);
    }
    
    void xor(byte[] in1, byte[] in2, byte[] out){
        for(short i=0; i<8; i++)
            out[i] = (byte)(in1[i] ^ in2[i]);
    }
    
    void and(byte[] in1, byte[] in2, byte[] out){
        for(short i=0; i<8; i++)
            out[i] = (byte)(in1[i] & in2[i]);
    }
    
    void not(byte[] in1, byte[] out){
        for(short i=0; i<8; i++)
            out[i] = (byte)(~in1[i]);
    }
    
    //alternative right rotation
    void rotLeft(byte[] arr, short shift, byte[] out) {
        
        Util.arrayCopyNonAtomic(arr, (short) (shift/8), out, (short) 0, (short) (8-(shift/8)));
        Util.arrayCopyNonAtomic(arr, (short) 0, out, (short) (8-(shift/8)), (short) (shift/8));
        shift %= 8; //now shift only up to 8 bits
        
        //rotate using masks
        if (shift > 0) {
            byte comp = (byte) (8 - shift);
            byte aux = (byte)(out[0] & ROT_MASK1[shift]);
            out[0] = (byte)((byte)(out[0] << shift) | (byte)((out[1] >> comp) & ROT_MASK2[shift]));
            out[1] = (byte)((byte)(out[1] << shift) | (byte)((out[2] >> comp) & ROT_MASK2[shift]));
            out[2] = (byte)((byte)(out[2] << shift) | (byte)((out[3] >> comp) & ROT_MASK2[shift]));
            out[3] = (byte)((byte)(out[3] << shift) | (byte)((out[4] >> comp) & ROT_MASK2[shift]));
            out[4] = (byte)((byte)(out[4] << shift) | (byte)((out[5] >> comp) & ROT_MASK2[shift]));
            out[5] = (byte)((byte)(out[5] << shift) | (byte)((out[6] >> comp) & ROT_MASK2[shift]));
            out[6] = (byte)((byte)(out[6] << shift) | (byte)((out[7] >> comp) & ROT_MASK2[shift]));
            out[7] = (byte)((byte)(out[7] << shift) | (byte)((aux    >> comp) & ROT_MASK2[shift]));
        }
    }
    
    void permutation(short rounds) {
        short i;
        
        Util.arrayCopyNonAtomic(S, (short)0, x0, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)8, x1, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)16, x2, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)24, x3, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)32, x4, (short)0, (short)8);
        Util.arrayCopyNonAtomic(S, (short)0, x4, (short)0, (short)8);
        
        
        for (i = 0; i < rounds; ++i) {
            // addition of round constant
            short tmp2 = (short)((short)((short)((short)(0xf) - i) << 4) | i);
            Util.arrayFillNonAtomic(t0, (short)0, (short)8, (byte)0);
            Util.setShort(t0, (short)6, tmp2);
            xor(x2, t0, x2);
            
            // substitution layer
            xor(x0, x4, x0);  xor(x4, x3, x4);  xor(x2, x1, x2);
            Util.arrayCopyNonAtomic(x0, (short)0, t0, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x1, (short)0, t1, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x2, (short)0, t2, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x3, (short)0, t3, (short)0, (short)8);
            Util.arrayCopyNonAtomic(x4, (short)0, t4, (short)0, (short)8);
            not(t0, t0);     not(t1, t1);     not(t2, t2);     not(t3, t3);     not(t4, t4);
            and(t0, x1, t0); and(t1, x2, t1); and(t2, x3, t2); and(t3, x4, t3); and(t4, x0, t4);
            xor(x0, t1, x0); xor(x1, t2, x1); xor(x2, t3, x2); xor(x3, t4, x3); xor(x4, t0, x4);
            xor(x1, x0, x1); xor(x0, x4, x0); xor(x3, x2, x3); not(x2, x2);
            
            // linear diffusion layer (all right rotations substituted by left rotation (64-shift)
            rotLeft(x0, (short)45, t0); rotLeft(x0, (short)36, t1); xor(t0, t1, t2); xor(x0, t2, x0);
            rotLeft(x1, (short) 3, t0); rotLeft(x1, (short)25, t1); xor(t0, t1, t2); xor(x1, t2, x1);
            rotLeft(x2, (short)63, t0); rotLeft(x2, (short)58, t1); xor(t0, t1, t2); xor(x2, t2, x2);
            rotLeft(x3, (short)54, t0); rotLeft(x3, (short)47, t1); xor(t0, t1, t2); xor(x3, t2, x3);
            rotLeft(x4, (short)57, t0); rotLeft(x4, (short)23, t1); xor(t0, t1, t2); xor(x4, t2, x4);
        }
        
        Util.arrayCopyNonAtomic(x0, (short)0, S, (short)0, (short)8);
        Util.arrayCopyNonAtomic(x1, (short)0, S, (short)8, (short)8);
        Util.arrayCopyNonAtomic(x2, (short)0, S, (short)16, (short)8);
        Util.arrayCopyNonAtomic(x3, (short)0, S, (short)24, (short)8);
        Util.arrayCopyNonAtomic(x4, (short)0, S, (short)32, (short)8);
    }
    
    public short encrypt(byte c[], short clen, byte m[], short mlen, byte ad[], short adlen,
                                     byte nsec[], byte npub[], byte k[]) {
        
        short klen = CRYPTO_KEYBYTES;
        //short size = (short)(320 / 8);
        short capacity = (short)((short)2 * klen);
        short rate = (short)(FORTY - capacity);
        short a = (short)12;
        short b = (klen == (short)16) ? (short)6 : (short)8;
        short s = (short)((short)(adlen / rate) + 1);
        short t = (short)((short)(mlen / rate) + 1);
        short l = (short)(mlen % rate);
        
        byte A[] = JCSystem.makeTransientByteArray((short) (s * rate), JCSystem.CLEAR_ON_DESELECT);
        byte M[] = JCSystem.makeTransientByteArray((short) (t * rate), JCSystem.CLEAR_ON_DESELECT);

        short i, j;
        
        // pad associated data
        for (i = 0; i < adlen; ++i)
            A[i] = ad[i];
        A[adlen] = (byte) 0x80;
        for (i = (short)(adlen + 1); i < (short)(s * rate); ++i)
            A[i] = 0;
        // pad plashortext
        for (i = 0; i < mlen; ++i)
            M[i] = m[i];
        M[mlen] = (byte) 0x80;
        for (i = (short)(mlen + 1); i < (short)(t * rate); ++i)
            M[i] = 0;
        

        // initialization
        S[0] = (byte) (klen * 8);
        S[1] = (byte) (rate * 8);
        S[2] = (byte) a;
        S[3] = (byte) b;
        for (i = 4; i < rate; ++i)
            S[i] = 0;
        for (i = 0; i < klen; ++i)
            S[(short)(rate + i)] = k[i];
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] = npub[i];
        

        permutation(a);

        
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] ^= k[i];

        
        // process associated data
        if (adlen != 0) {
            for (i = 0; i < s; ++i) {
                for (j = 0; j < rate; ++j)
                    S[j] ^= A[(short)(i * rate + j)];
                permutation(b);
            }
        }
        S[(short)(FORTY - 1)] ^= 1;

        
        // process plaintext
        for (i = 0; i < (short) (t - 1); ++i) {
            for (j = 0; j < rate; ++j) {
                S[j] ^= M[(short)(i * rate + j)];
                c[(short)(i * rate + j)] = S[j];
            }
            permutation(b);
        }

        for (j = 0; j < rate; ++j)
            S[j] ^= M[(short) ((short) (t - 1) * rate + j)];
        for (j = 0; j < l; ++j)
            c[(short) ((short) (t - 1) * rate + j)] = S[j];

        
        // finalization & tag generation
        for (i = 0; i < klen; ++i)
            S[(short)(rate + i)] ^= k[i];
        permutation(a);
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] ^= k[i];
        // return tag
        for (i = 0; i < klen; ++i)
            c[(short)(mlen + i)] = S[(short)(rate + klen + i)];
        clen = (short)(mlen + klen);
        
        return clen;
    }
    
    public short decrypt(byte m[], short mlen, byte nsec[], byte c[], short clen, byte ad[],
                                     short adlen, byte npub[], byte k[]) {
        
        mlen = 0;
        if (clen < CRYPTO_KEYBYTES)
            return -1;
        
        short klen = CRYPTO_KEYBYTES;
        short capacity = (short)(2 * klen);
        short rate = (short)(FORTY - capacity);
        short a = (short) 12;
        short b = (klen == (short) 16) ? (short)6 : (short)8;
        short s = (short)((short)(adlen / rate) + 1);
        short t = (short)((short)((short)(clen - klen) / rate) + 1);
        short l = (short)((short)(clen - klen) % rate);

        byte A[] = JCSystem.makeTransientByteArray((short) (s * rate), JCSystem.CLEAR_ON_DESELECT);
        byte M[] = JCSystem.makeTransientByteArray((short) (t * rate), JCSystem.CLEAR_ON_DESELECT);
        short i, j;
        
        // pad associated data
        for (i = 0; i < adlen; ++i)
            A[i] = ad[i];
        A[adlen] = (byte) 0x80;
        for (i = (short)(adlen + 1); i < (short) (s * rate); ++i)
            A[i] = 0;
        
        // initialization
        S[0] = (byte) (klen * 8);
        S[1] = (byte) (rate * 8);
        S[2] = (byte) a;
        S[3] = (byte) b;
        for (i = 4; i < rate; ++i)
            S[i] = 0;
        for (i = 0; i < klen; ++i)
            S[(short) (rate + i)] = k[i];
        for (i = 0; i < klen; ++i)
            S[(short) (rate + klen + i)] = npub[i];
        permutation(a);
        for (i = 0; i < klen; ++i)
            S[(short) (rate + klen + i)] ^= k[i];
        
        // process associated data
        if (adlen != 0) {
            for (i = 0; i < s; ++i) {
                for (j = 0; j < rate; ++j)
                    S[j] ^= A[(short) (i * rate + j)];
                permutation(b);
            }
        }
        S[(short) (FORTY - 1)] ^= 1;
        
        // process plaintext
        for (i = 0; i < (short)(t - 1); ++i) {
            for (j = 0; j < rate; ++j) {
                M[(short)(i * rate + j)] = (byte) (S[j] ^ c[(short)(i * rate + j)]);
                S[j] = c[(short)(i * rate + j)];
            }
            permutation(b);
        }
        for (j = 0; j < l; ++j)
            M[(short) ((short)(t - 1) * rate + j)] = (byte) (S[j] ^ c[(short) ((short)(t - 1) * rate + j)]);
        for (j = 0; j < l; ++j)
            S[j] = c[(short) ((short)(t - 1) * rate + j)];
        S[l] ^= 0x80;
        
        // finalization
        for (i = 0; i < klen; ++i)
            S[(short)(rate + i)] ^= k[i];
        permutation(a);
        for (i = 0; i < klen; ++i)
            S[(short)(rate + klen + i)] ^= k[i];
        
        // return -1 if verification fails
        for (i = 0; i < klen; ++i)
            if (c[(short)(clen - klen + i)] != S[(short)(rate + klen + i)])
                return -1;
        
        // return plaintext
        mlen = (short)(clen - klen);
        for (i = 0; i < mlen; ++i)
            m[i] = M[i];
        
        return mlen;
    }
}
