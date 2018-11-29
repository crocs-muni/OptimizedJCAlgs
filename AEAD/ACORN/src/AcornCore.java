package acorn;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 *
 * @author Rajesh Kumar Pal
 * 21 Oct 2017
 * @review Matej Evin
 * 09 Oct 2018
 * 
 * Optimizations:
 * 
 * removed tempbuf
 * simplified byte shifts
 * removed redundant arrays
 * inlined functions
 * unrolled some loops
 * removed 1536 bytes of EEPROM
 * removed 1536 writes into EEPROM (this is huge)
 * changed visibility
 * 
 */
public class AcornCore {
    
    // Defines
    public final static short LEN       = 16;
    public final static byte SUCCESS    = 0;
    public final static byte KEY_ERROR  = -1;
    
    private byte[] mac          = null;     // authentication tag
    private byte[] state        = null;     // state
    private byte[] userkey      = null;     // user inputed encryption key
    private byte[] ct           = null;     // ciphertext
    private byte[] pt           = null;     // plaintext
    private byte[] ad           = null;     // authenticated data
    private byte[] nonce        = null;     // public message number
    private short ctlen         = 0;
    private short ptlen         = 0;
    private short adlen         = 0;
    private byte plaintextbyte, ciphertextbyte, plaintextbit, ciphertextbit;
    private byte ks, ksbyte;
    
    public AcornCore(){
        state = JCSystem.makeTransientByteArray((short)293, JCSystem.CLEAR_ON_DESELECT);
        mac = JCSystem.makeTransientByteArray(LEN, JCSystem.CLEAR_ON_DESELECT);
    }
    
    // The initialization state of Acorn
    // The input to initialization is the 128-bit key; 128-bit IV;
    public byte init(byte[] nsecret, byte[] npublic, byte[] key, short keylen) {
        if(keylen != LEN){
            return KEY_ERROR;
        }
        userkey = key;
        nonce = npublic;  // iv
        
        short i;
        
        //initialize the state to 0
        Util.arrayFillNonAtomic(state, (short)0, (short)293, (byte)0x00);
        
        ks = 0;
        
        //set the value of m
        for(i = 0; i <= 127; i++) {
            plaintextbit = (byte)( (byte)( userkey[(byte)(i/8)] >> (byte)(i & 7) ) & (byte)0x1);
            Encrypt_StateUpdate128((byte)0x01, (byte)0x01);
        }
        
        for(i = 0; i <= 127; i++) {
            plaintextbit = (byte)( (byte)( nonce[(byte)(i/8)]  >> (byte)(i & 7) ) & (byte)0x1);
            Encrypt_StateUpdate128((byte)0x01, (byte)0x01);
        }
        
        plaintextbit = 1;
        Encrypt_StateUpdate128((byte)0x01, (byte)0x01);
        
        //Util.arrayFillNonAtomic(m, (short)257, (short)1279, (byte)0x00);
        
        plaintextbit = 0;
        
        //run the cipher for 1536 steps
        for (i = 0; i < 1279; i++) {
            Encrypt_StateUpdate128((byte)0x01, (byte)0x01);
        }
        return SUCCESS;
    }
    
    //encrypt one bit (input: plaintextbit, output: ciphertextbit)
    byte Encrypt_StateUpdate128(byte ca, byte cb) {
        byte f;
        state[(short)289] ^= (byte)(state[(short)235] ^ state[(short)230]);
        state[(short)230] ^= (byte)(state[(short)196] ^ state[(short)193]);
        state[(short)193] ^= (byte)(state[(short)160] ^ state[(short)154]);
        state[(short)154] ^= (byte)(state[(short)111] ^ state[(short)107]);
        state[(short)107] ^= (byte)(state[(short)66]  ^ state[(short)61]);
        state[(short)61]  ^= (byte)(state[(short)23]  ^ state[(short)0]);
        
        ks = (byte)(state[(short)12] ^ state[(short)154] ^ ((byte)( (byte)(state[(short)235] & state[(short)61]) ^ (byte)(state[(short)235] & state[(short)193]) ^ (byte)(state[(short)61] & state[(short)193]))));
        f =  (byte)(state[(short)0] ^ (byte)(state[(short)107] ^ (byte)1) ^ ((byte)( (byte)(state[(short)244] & state[(short)23]) ^ (byte)(state[(short)244] & state[(short)160]) ^ (byte)(state[(short)23] & state[(short)160])))
               ^ ((byte)( (byte)(state[(short)230] & state[(short)111]) ^ (byte)( (byte)(state[(short)230] ^ 1) & state[(short)66]))) ^ (byte)(ca & state[(short)196]) ^ (byte)(cb & ks));
        
        Util.arrayCopyNonAtomic(state, (short)1, state, (short)0, (short)292); //byte shift
        state[(short)292] = (byte)(f ^ plaintextbit);
        ciphertextbit = (byte)(ks ^ plaintextbit);
        
        return SUCCESS;
    }
    
    //decrypt one bit (input: ciphertextbit, output: plaintextbit)
    byte Decrypt_StateUpdate128(byte ca, byte cb) {
        byte f;
        state[(short)289] ^= (byte)(state[(short)235] ^ state[(short)230]);
        state[(short)230] ^= (byte)(state[(short)196] ^ state[(short)193]);
        state[(short)193] ^= (byte)(state[(short)160] ^ state[(short)154]);
        state[(short)154] ^= (byte)(state[(short)111] ^ state[(short)107]);
        state[(short)107] ^= (byte)(state[(short)66]  ^ state[(short)61]);
        state[(short)61]  ^= (byte)(state[(short)23]  ^ state[(short)0]);
        
        ks = (byte)(state[(short)12] ^ state[(short)154] ^ ((byte)( (byte)(state[(short)235] & state[(short)61]) ^ (byte)(state[(short)235] & state[(short)193]) ^ (byte)(state[(short)61] & state[(short)193]))));
        f =  (byte)(state[(short)0] ^ (byte)(state[(short)107] ^ (byte)1) ^ ((byte)( (byte)(state[(short)244] & state[(short)23]) ^ (byte)(state[(short)244] & state[(short)160]) ^ (byte)(state[(short)23] & state[(short)160])))
               ^ ((byte)( (byte)(state[(short)230] & state[(short)111]) ^ (byte)( (byte)(state[(short)230] ^ 1) & state[(short)66]))) ^ (byte)(ca & state[(short)196]) ^ (byte)(cb & ks) );
        
        Util.arrayCopyNonAtomic(state, (short)1, state, (short)0, (short)292); //byte shift
        plaintextbit = (byte)(ks ^ ciphertextbit);
        state[(short)292] = (byte)(f ^ plaintextbit);
        
        return SUCCESS;
    }
    
    // encrypt one byte
    byte acorn128_enc_onebyte(byte cabyte, byte cbbyte) {
        byte caBit, cbBit, i;
        ciphertextbyte = (byte)0x00;
        ksbyte = 0;
        ks = 0;
        for(i = 0; i < 8; i++) {
            caBit = (byte)( (byte)(cabyte >> i) & (byte)1);
            cbBit = (byte)( (byte)(cbbyte >> i) & (byte)1);
            plaintextbit = (byte)( (byte)(plaintextbyte >> i) & (byte)1);
            Encrypt_StateUpdate128(caBit, cbBit);
            ciphertextbyte |= (byte)(ciphertextbit << i);
            ksbyte |= (byte)(ks << i);
        }
        return SUCCESS;
    }
    
    // decrypt one byte
    byte acorn128_dec_onebyte(byte cabyte, byte cbbyte) {
        byte caBit, cbBit, i;
        plaintextbyte = (byte)0x00;
        ksbyte = 0;
        ks = 0;
        for(i = 0; i < 8; i++) {
            caBit = (byte)( (byte)(cabyte >> i) & (byte)1);
            cbBit = (byte)( (byte)(cbbyte >> i) & (byte)1);
            ciphertextbit = (byte)( (byte)(ciphertextbyte >> i) & (byte)1);
            Decrypt_StateUpdate128(caBit, cbBit);
            plaintextbyte |= (byte)(plaintextbit << i);
        }
        return SUCCESS;
    }
    
    public byte encrypt(byte[] cipher, short cipherlen, byte[] message, short messagelen, byte[] authdata, short authdatalen) {
        byte i;
        byte ca, cb;
        short j;
        
        ct = cipher;
        ctlen = cipherlen;
        pt = message;
        ptlen = messagelen;
        ad = authdata;
        adlen = authdatalen;
        
        //process the associated data
        for(i = 0; i < adlen; i++) {
            plaintextbyte = ad[i];
            acorn128_enc_onebyte((byte)0xff, (byte)0xff);
        }
        
        for(i = 0; i < 64; i++) {
            if ( i != 0 ) plaintextbyte = 0;
            else plaintextbyte = 1;
            
            if ( i < 32 ) ca = (byte)0xff;
            else ca = (byte)0x00;
            
            cb = (byte)0xff;
            acorn128_enc_onebyte(ca, cb);
        }
        
        //process the plaintext
        for(j = 0; j < ptlen; j++) {
            plaintextbyte = pt[j];
            acorn128_enc_onebyte((byte)0xff, (byte)0x00);
            ct[j] = ciphertextbyte;
        }
        
        for(i = 0; i < 64; i++) {
            if ( i == 0 ) plaintextbyte = 1;
            else plaintextbyte = 0;
            
            if ( i < 32)   ca = (byte)0xff;
            else ca = (byte)0x00;
            
            cb = (byte)0x00;
            
            acorn128_enc_onebyte(ca, cb);
        }
        
        //finalization stage, we assume that the tag length is a multiple of bytes
        //tag generation
        plaintextbyte = 0;
        ciphertextbyte = 0;
        ksbyte = 0;
        for(i = 0; i < 64; i++) {
            acorn128_enc_onebyte((byte)0xff, (byte)0xff);
            if ( i >= 48 ) {
                mac[(byte)(i-(byte)((byte)(512/8)-16))] = ksbyte;
            }
        }
        ctlen = (short)(ptlen + 16);
        Util.arrayCopyNonAtomic(mac, (short)0, ct, ptlen, LEN);
        
        return SUCCESS;
    }
    
    public byte decrypt(byte[] cipher, short cipherlen, byte[] message, short messagelen, byte[] authdata, short authdatalen) {
        byte i;
        byte ca, cb;
        short j;
        byte check = 0;
        
        if(cipherlen < 16) return -1;
        
        ct = cipher;
        ctlen = cipherlen;
        pt = message;
        ptlen = messagelen;
        ad = authdata;
        adlen = authdatalen;
        
        //process the associated data
        for(i = 0; i < adlen; i++) {
            plaintextbyte = ad[i];
            acorn128_enc_onebyte((byte)0xff, (byte)0xff);
        }
        
        for(i = 0; i < 64; i++) {
            if ( i != 0 ) plaintextbyte = 0;
            else plaintextbyte = 1;
            
            if ( i < 32)   ca = (byte)0xff;
            else ca = (byte)0x00;
            
            cb = (byte)0xff;
            
            acorn128_enc_onebyte(ca, cb);
        }
        
        //process the plaintext
        ptlen = (short)(ctlen - 16);
        for(j = 0; j < ptlen; j++) {
            ciphertextbyte = ct[j];
            acorn128_dec_onebyte((byte)0xff, (byte)0x00);
            pt[j] = plaintextbyte;
        }
        
        for(i = 0; i < 64; i++) {
            if ( i == 0 ) plaintextbyte = 1;
            else plaintextbyte = 0;
            
            if ( i < 32)   ca = (byte)0xff;
            else ca = (byte)0x00;
            
            cb = (byte)0x00;
            
            acorn128_enc_onebyte(ca, cb);
        }
        
        //finalization stage, we assume that the tag length is a multiple of bytes
        //tag generation
        plaintextbyte = 0;
        ciphertextbyte = 0;
        ksbyte = 0;      
        for(i = 0; i < 64; i++) {
            acorn128_enc_onebyte((byte)0xff, (byte)0xff);
            if ( i >= 48 ) {
                mac[(byte)(i-(byte)((byte)(512/8)-16))] = ksbyte;
            }
        }
        for(i = 0; i < 16; i++) check |= (mac[i] ^ ct[(short)(ctlen - 16 + i)]);
        
        if (check == 0)  return SUCCESS;
        else return -1;        
    }
}
