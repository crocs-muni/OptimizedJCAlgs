package cloc;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 *
 * @author Rajesh Kumar Pal
 * 15 Oct 2017
 * @review Matej Evin
 * 12 Oct 2018
 * 
 * removed redundant ram arrays
 * removed redundant variables
 * removed unused decryptCipher
 * inlined some function calls
 * removed software AES implementation
 * moved functionality to init instead of encrypt/decrypt
 * 
 * Original time: 690ms
 * Optimized time: 437ms
 * Time reduced to 63%
 * Original size 8kb
 * Optimized size 7kb
 * 
 */
public class ClocCore {
  // Engines
  private   AESKey         m_aesKey             = null;
  private   Cipher         m_encryptCipher      = null;
   
  // Defines
  public final static byte PARAM                = (byte)0xc0;
  public final static byte STATE_LEN            = 16;
  public final static byte AD_ERROR             = -2;
  public final static byte KEY_ERROR            = -1;
  public final static byte SUCCESS              = 0;
  public final static byte ENC                  = 1;
  public final static byte DEC                  = 2;
  public final static byte RETURN_SUCCESS       = 0;
  public final static byte RETURN_TAG_NO_MATCH  = -1;
  public final static byte RETURN_MEMORY_FAIL   = -2;
  public final static byte RETURN_KEYSIZE_ERR   = -3;
  
  private byte[] es         = null;     // encryption state
  private byte[] ts         = null;     // tag processing state
  private byte[] userkey    = null;     // user inputed encryption key
  private byte[] ad         = null;     // authenticated data
  private byte[] nonce      = null;     // public message number
  private byte[] tag        = null;     // authentication tag
  private byte[] pt         = null;     // plaintext
  private byte[] ct         = null;     // ciphertext
  private byte[] tmp        = null;     // temporary values for computation
  private short nlen        = 0;
  private short adlen       = 0;
  private short ptlen       = 0;
  private short ctlen       = 0;
  
  public ClocCore(){
      es = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
      ts = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
      tag = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
      tmp = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
      
      // CREATE AES KEY OBJECT
      m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
      // CREATE OBJECTS FOR CBC CIPHERING
      m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
  }
  
  public byte init(byte[] nsecret, byte[] npublic, byte[] key, short keylen){
      
      // change endiannesss of key
      if(keylen != STATE_LEN){
          return KEY_ERROR;
      }
      userkey = key;
      // SET KEY VALUE
      m_aesKey.setKey(userkey, (short) 0);

      // INIT CIPHERS WITH NEW KEY
      m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      
      nonce = npublic;
      nlen = (short)nonce.length;  //max can be 12 as per specifications
      return SUCCESS;
  }
  
    public byte encrypt(byte[] message, short messagelen, byte[] ciphertext, byte[] authdata, short authdatalen) {
      
        ad = authdata;
        adlen = authdatalen;
        ct = ciphertext;
        pt = message;
        ptlen = messagelen;
        ctlen = (short)(ptlen + 8);

        //process the associated data
        process_ad();

        // encrypt message
        ae(ENC);

        // copy the tag to the end of ciphertext
        Util.arrayCopyNonAtomic(tag, (short)0, ct, ptlen, (short)8);

        return SUCCESS;
    }
  
    public byte decrypt(byte[] ciphertext, short ciphertextLen, byte[] plaintext, byte[] authdata, short authdatalen) {
        
        ad = authdata;
        adlen = authdatalen;
        ct = ciphertext;
        ctlen = ciphertextLen;
        pt = plaintext;
        ptlen = (short)(ctlen - 8);
      
        //process the associated data
        process_ad();
      
        // decrypt ciphertext
        ae(DEC);
      
        // compare the tag 
        byte ret = Util.arrayCompare(tag, (short)0, ct, ptlen, (short)8);
        if(ret !=0 ) return RETURN_TAG_NO_MATCH;
      
        return SUCCESS;
    }
  
    byte process_ad() {
        // process the first block
        byte ozp = 0;
        if(adlen < STATE_LEN){       // less than one block
            Util.arrayFillNonAtomic(es, (short)0, (short)16, (byte)0x00);
            Util.arrayCopyNonAtomic(ad, (short)0, es, (short)0,  adlen);
            es[adlen] = (byte)0x80;
            ozp = 1;
        }
        else{     // full first block
            Util.arrayCopyNonAtomic(ad, (short)0, es, (short)0,  STATE_LEN); 
        }

        // apply fix0 and the E_k
        byte fix0 = (byte)(es[0] & (byte)0x80);    // test if the MSB is zero
        es[0] &= (byte)0x7f;

        // apply the first encryption
        m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);

        // when fix0 works, apply h
        if(fix0 == 1) {
            es[0]  ^= es[4];  es[1]  ^= es[5];  es[2]  ^= es[6];  es[3]  ^= es[7];         
            es[4]  ^= es[8];  es[5]  ^= es[9];  es[6]  ^= es[10]; es[7]  ^= es[11];          
            es[8]  ^= es[12]; es[9]  ^= es[13]; es[10] ^= es[14]; es[11] ^= es[15];          
            es[12] ^= es[0];  es[13] ^= es[1];  es[14] ^= es[2];  es[15] ^= es[3];
        }

        // process the middle normal blocks of ad
        short j;
        for(j=1; j<(short)(adlen/STATE_LEN); j++) {
            for(short i=0; i<16; i++)
                es[i] ^= ad[(short)(i + (short)(16*j))];
            m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
        }
        // process the last block partial block if any
        short lastblocklen = (short)(adlen % STATE_LEN);
        if((adlen > STATE_LEN) && lastblocklen != 0){
            //xor bytes ad last block
            for(short i = 0; i < lastblocklen; i++)
                es[i] = (byte)(es[i] ^ ad[(short)(i + (short)(16*j))]);
            es[lastblocklen] ^= 0x80;
            m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
            ozp = 1;
        }

        // * process the nonce
        // * 1. first byte is: PARAM
        // * 2. then the nonce value
        // * 3. padding if any (at the moment, the parameter set
        // contains padding for all choices)
        es[0] ^= PARAM;
        //xor bytes nonce
        for(short i = 0; i < nlen; i++)
            es[(short)(i+1)] = (byte)(es[(short)(i+1)] ^ nonce[i]);
        // apply padding to nonce
        if((short)(nlen+1) != STATE_LEN)
        es[(short)(nlen+1)] ^= 0x80;
        if(ozp == 1) {
            tmp[0] = (byte)(es[0] ^ es[4]); tmp[1] = (byte)(es[1] ^ es[5]); tmp[2] = (byte)(es[2] ^ es[6]); tmp[3] = (byte)(es[3] ^ es[7]);         
            es[0] = es[4]; es[1] = es[5]; es[2] = es[6]; es[3] = es[7];         
            es[4] = es[8]; es[5] = es[9]; es[6] = es[10]; es[7] = es[11];          
            es[8] = es[12]; es[9] = es[13]; es[10] = es[14]; es[11] = es[15];          
            es[12] = tmp[0]; es[13] = tmp[1]; es[14] = tmp[2]; es[15] = tmp[3];
        } else {
            es[0] ^= es[8]; es[1] ^= es[9]; es[2] ^= es[10]; es[3] ^= es[11];         
            tmp[0] = es[4]; tmp[1] = es[5]; tmp[2] = es[6]; tmp[3] = es[7];      
            es[4] ^= es[12]; es[5] ^= es[13]; es[6] ^= es[14]; es[7] ^= es[15];         
            es[12] = (byte)(es[8] ^ es[4]); es[13] = (byte)(es[9] ^ es[5]); es[14] = (byte)(es[10] ^ es[6]); es[15] = (byte)(es[11] ^ es[7]);         
            es[8] = (byte)(tmp[0] ^ es[0]); es[9] = (byte)(tmp[1] ^ es[1]); es[10] = (byte)(tmp[2] ^ es[2]); es[11] = (byte)(tmp[3] ^ es[3]);
        }
        Util.arrayCopyNonAtomic(es, (short)0, ts, (short)0,  STATE_LEN); 
        m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);

        return SUCCESS;
    }
  
    byte ae(byte enc_dec) {
        if(ptlen != 0) {
            tmp[0] = (byte)(ts[0] ^ ts[4]); tmp[1] = (byte)(ts[1] ^ ts[5]); tmp[2] = (byte)(ts[2] ^ ts[6]); tmp[3] = (byte)(ts[3] ^ ts[7]);         
            ts[0] = ts[4]; ts[1] = ts[5]; ts[2] = ts[6]; ts[3] = ts[7];         
            ts[4] = ts[8]; ts[5] = ts[9]; ts[6] = ts[10]; ts[7] = ts[11];          
            ts[8] = ts[12]; ts[9] = ts[13]; ts[10] = ts[14]; ts[11] = ts[15];          
            ts[12] = tmp[0]; ts[13] = tmp[1]; ts[14] = tmp[2]; ts[15] = tmp[3];
            m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
        }
        else {
            tmp[0] = ts[0]; tmp[1] = ts[1]; tmp[2] = ts[2]; tmp[3] = ts[3];         
            ts[0] = ts[8]; ts[1] = ts[9]; ts[2] = ts[10]; ts[3] = ts[11];         
            ts[8] = (byte)(tmp[0] ^ ts[4]); ts[9] = (byte)(tmp[1] ^ ts[5]); ts[10] = (byte)(tmp[2] ^ ts[6]); ts[11] = (byte)(tmp[3] ^ ts[7]);         
            tmp[0] = ts[4]; tmp[1] = ts[5]; tmp[2] = ts[6]; tmp[3] = ts[7];      
            ts[4] = ts[12]; ts[5] = ts[13]; ts[6] = ts[14]; ts[7] = ts[15];         
            ts[12] = (byte)(ts[0] ^ tmp[0]); ts[13] = (byte)(ts[1] ^ tmp[1]); ts[14] = (byte)(ts[2] ^ tmp[2]); ts[15] = (byte)(ts[3] ^ tmp[3]);
            m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
            Util.arrayCopyNonAtomic(ts, (short)0, tag, (short)0,  (short)8);
        }

        short pc = 0;
        while((short)(pc + STATE_LEN) < ptlen){
            if(enc_dec == ENC) { // encryption
                for(short i=0; i<16; i++)
                    es[i] ^= pt[(short)(i + pc)];
                Util.arrayCopyNonAtomic(es, (short)0, ct, pc, STATE_LEN);
            }
            else { // decryption
                for(short i = 0; i < 16; i++)
                    pt[(short)(i + pc)] = (byte)(es[i] ^ ct[(short)(i + pc)]);
                Util.arrayCopyNonAtomic(ct, pc, es, (short)0, STATE_LEN);

            }
            for(short i=0; i<16; i++)
                ts[i] ^= es[i];
            m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
            // apply fix1
            es[0] |= (byte)0x80;
            m_encryptCipher.doFinal(es, (short)0, (short)16, es, (short) 0);
            pc += STATE_LEN;
        }

        // process the last block
        short lastblocklen = (short)(ptlen - pc);
        if(enc_dec == ENC) { // encryption
            for(short i = 0; i < lastblocklen; i++)
                es[i] = (byte)(es[i] ^ pt[(short)(i + pc)]);
            Util.arrayCopyNonAtomic(es, (short)0, ct, pc, lastblocklen);
        }
        else{ // decryption
            for(short i = 0; i < lastblocklen; i++)
                pt[(short)(i + pc)] = (byte)(es[i] ^ ct[(short)(i + pc)]);
            Util.arrayCopyNonAtomic(ct, pc, es, (short)0, lastblocklen);

        }
        for(short i = 0; i < lastblocklen; i++)
            ts[i] = (byte)(ts[i] ^ es[i]);
        if(lastblocklen != STATE_LEN) {
            ts[lastblocklen] ^= (byte)0x80;
            tmp[0] = (byte)(ts[0] ^ ts[4]); tmp[1] = (byte)(ts[1] ^ ts[5]); tmp[2] = (byte)(ts[2] ^ ts[6]); tmp[3] = (byte)(ts[3] ^ ts[7]);         
            ts[0] = ts[4]; ts[1] = ts[5]; ts[2] = ts[6]; ts[3] = ts[7];         
            ts[4] = ts[8]; ts[5] = ts[9]; ts[6] = ts[10]; ts[7] = ts[11];          
            ts[8] = ts[12]; ts[9] = ts[13]; ts[10] = ts[14]; ts[11] = ts[15];          
            ts[12] = tmp[0]; ts[13] = tmp[1]; ts[14] = tmp[2]; ts[15] = tmp[3];
        }
        else {
            ts[0] ^= ts[8]; ts[1] ^= ts[9]; ts[2] ^= ts[10]; ts[3] ^= ts[11];         
            tmp[0] = ts[4]; tmp[1] = ts[5]; tmp[2] = ts[6]; tmp[3] = ts[7];      
            ts[4]  ^= ts[12]; ts[5] ^= ts[13]; ts[6] ^= ts[14]; ts[7] ^= ts[15];         
            ts[12]  = (byte)(ts[8]  ^ ts[4]); ts[13] = (byte)(ts[9]  ^ ts[5]);
            ts[14]  = (byte)(ts[10] ^ ts[6]); ts[15] = (byte)(ts[11] ^ ts[7]);         
            ts[8]   = (byte)(tmp[0] ^ ts[0]); ts[9]  = (byte)(tmp[1] ^ ts[1]);
            ts[10]  = (byte)(tmp[2] ^ ts[2]); ts[11] = (byte)(tmp[3] ^ ts[3]);
        }

        m_encryptCipher.doFinal(ts, (short)0, (short)16, ts, (short) 0);
        Util.arrayCopyNonAtomic(ts, (short)0, tag, (short)0, (short)8);

        return SUCCESS;
    }
}

