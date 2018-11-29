package morus;

//import javacard.framework.*;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 *
 * @author Rajesh Kumar Pal
 * 15 Oct 2017
 * @review Matej Evin
 * 28 Nov 2018
 * 
 * removed redundant variables and temporaries
 * reduced method visibility to package only
 * inlined many function calls
 * improved byte shifting
 * moved many parts to init, especially slow parts - better interface
 * unrolled many loops
 * 
 */

public class MorusCore {

    // Defines
    public final static short CRYPTO_KEYBYTES   = 16;
    public final static short CRYPTO_NSECBYTES  = 0;
    public final static short CRYPTO_NPUBBYTES  = 16;
    public final static short CRYPTO_ABYTES     = 16;
    public final static short CRYPTO_NOOVERLAP  = 1;

    //public byte i = 0;

    private byte[] state            = null;
    private byte[] plaintextblock   = null;
    private byte[] ciphertextblock  = null;
    private byte[] c                = null;
    private byte[] m                = null;
    private byte[] ad               = null;
    private byte[] npub             = null;
    private byte[] k                = null;
    private byte[] tempbuf          = null;
    private short clen              = 0;
    private short mlen              = 0;
    private short adlen             = 0;
    private byte temp1;
  
    public MorusCore(){//public
        state           = JCSystem.makeTransientByteArray((short)80, JCSystem.CLEAR_ON_DESELECT);
        plaintextblock  = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        ciphertextblock = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        tempbuf         = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
    }
  
    public void init(byte[] nsecret,  byte[] npublic, byte[] key) {
        
        // change endiannesss of key
        changeEndianness((short)0, (short)16, key);
        k = key;

        // change endiannesss of nsec
        changeEndianness((short)0, (short)16, nsecret);
        // change endiannesss of npub
        changeEndianness((short)0, (short)16, npublic);
        npub = npublic;
        
        // initialization
        morus_initialization(); //BOTTLENECK

    }

    void changeEndianness(short startIndex, short endIndex, byte[] src) {
        for(short i=startIndex; (short)(i+3)<endIndex; i=(short)(i+4)){
            temp1 = src[i];
            src[i] = src[(short)(i+3)];
            src[(short)(i+3)] = temp1;
            temp1 = src[(short)(i+1)];
            src[(short)(i+1)] = src[(short)(i+2)];
            src[(short)(i+2)] = temp1;
        }
    }
  
    void xor(byte srcdstIndex, byte inpIndex){
          for(byte i=0; i<16; i++)
                state[(byte)(srcdstIndex+i)] ^= state[(byte)(inpIndex+i)];
    }
    
    void xorMsg(byte Index, byte[] msgblk){
        for(byte i=0; i<16; i++)
            state[(byte)(Index+i)] ^= msgblk[i];
    }
    
    void andxor(byte dstIndex, byte inp1Index, byte inp2Index){
        for(byte i=0; i<16; i++)
            state[(byte)(dstIndex+i)] ^= (byte)(state[(byte)(inp1Index+i)] & state[(byte)(inp2Index+i)]);
    }
    
    void morus_stateupdate(byte[] msgblk){
        
        byte tmp;
        
        // part 1
        xor((byte)0, (byte)48);
        andxor((byte)0, (byte)16, (byte)32);
        //rotate 5; block 0-15
        tmp = state[0];
        state[0] = (byte)((byte)(state[0] << 5) | (byte)((state[1] >> 3) & 0x1F));
        state[1] = (byte)((byte)(state[1] << 5) | (byte)((state[2] >> 3) & 0x1F));
        state[2] = (byte)((byte)(state[2] << 5) | (byte)((state[3] >> 3) & 0x1F));
        state[3] = (byte)((byte)(state[3] << 5) | (byte)((tmp      >> 3) & 0x1F));
        tmp = state[4];
        state[4] = (byte)((byte)(state[4] << 5) | (byte)((state[5] >> 3) & 0x1F));
        state[5] = (byte)((byte)(state[5] << 5) | (byte)((state[6] >> 3) & 0x1F));
        state[6] = (byte)((byte)(state[6] << 5) | (byte)((state[7] >> 3) & 0x1F));
        state[7] = (byte)((byte)(state[7] << 5) | (byte)((tmp      >> 3) & 0x1F));
        tmp = state[8];
        state[8] =  (byte)((byte)(state[8]  << 5) | (byte)((state[9]  >> 3) & 0x1F));
        state[9] =  (byte)((byte)(state[9]  << 5) | (byte)((state[10] >> 3) & 0x1F));
        state[10] = (byte)((byte)(state[10] << 5) | (byte)((state[11] >> 3) & 0x1F));
        state[11] = (byte)((byte)(state[11] << 5) | (byte)((tmp       >> 3) & 0x1F));
        tmp = state[12];
        state[12] = (byte)((byte)(state[12] << 5) | (byte)((state[13] >> 3) & 0x1F));
        state[13] = (byte)((byte)(state[13] << 5) | (byte)((state[14] >> 3) & 0x1F));
        state[14] = (byte)((byte)(state[14] << 5) | (byte)((state[15] >> 3) & 0x1F));
        state[15] = (byte)((byte)(state[15] << 5) | (byte)((tmp       >> 3) & 0x1F));
        
        //optimized
        Util.arrayCopyNonAtomic(state,   (short) 48, tempbuf, (short)  0, (short) 16);
        Util.arrayCopyNonAtomic(tempbuf, (short) 12, state,   (short) 48, (short)  4);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 52, (short) 12);
        
        // part 2
        xorMsg((byte)16, msgblk);
        xor((byte)16, (byte)64);
        andxor((byte)16, (byte)32, (byte)48);
        // rotate left 31 (1 to the right); block 16-31
        tmp = state[31];
        state[31] = (byte)((byte)((state[31] >> 1) & 0x7F) | (byte)(state[30] << 7));
        state[30] = (byte)((byte)((state[30] >> 1) & 0x7F) | (byte)(state[29] << 7));
        state[29] = (byte)((byte)((state[29] >> 1) & 0x7F) | (byte)(state[28] << 7));
        state[28] = (byte)((byte)((state[28] >> 1) & 0x7F) | (byte)(tmp       << 7));
        tmp = state[27];
        state[27] = (byte)((byte)((state[27] >> 1) & 0x7F) | (byte)(state[26] << 7));
        state[26] = (byte)((byte)((state[26] >> 1) & 0x7F) | (byte)(state[25] << 7));
        state[25] = (byte)((byte)((state[25] >> 1) & 0x7F) | (byte)(state[24] << 7));
        state[24] = (byte)((byte)((state[24] >> 1) & 0x7F) | (byte)(tmp       << 7));
        tmp = state[23];
        state[23] = (byte)((byte)((state[23] >> 1) & 0x7F) | (byte)(state[22] << 7));
        state[22] = (byte)((byte)((state[22] >> 1) & 0x7F) | (byte)(state[21] << 7));
        state[21] = (byte)((byte)((state[21] >> 1) & 0x7F) | (byte)(state[20] << 7));
        state[20] = (byte)((byte)((state[20] >> 1) & 0x7F) | (byte)(tmp       << 7));
        tmp = state[19];
        state[19] = (byte)((byte)((state[19] >> 1) & 0x7F) | (byte)(state[18] << 7));
        state[18] = (byte)((byte)((state[18] >> 1) & 0x7F) | (byte)(state[17] << 7));
        state[17] = (byte)((byte)((state[17] >> 1) & 0x7F) | (byte)(state[16] << 7));
        state[16] = (byte)((byte)((state[16] >> 1) & 0x7F) | (byte)(tmp       << 7));
        
        //optimized
        Util.arrayCopyNonAtomic(state,   (short) 64, tempbuf, (short)  0, (short) 8);
        Util.arrayCopyNonAtomic(state,   (short) 72, state,   (short) 64, (short) 8);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 72, (short) 8);
        
        // part 3
        xorMsg((byte)32, msgblk);
        xor((byte)32, (byte)0);
        andxor((byte)32, (byte)48, (byte)64);
        // rotate 7, block 3
        
        tmp = state[32];
        state[32] = (byte)((byte)(state[32] << 7) | (byte)((state[33] >> 1) & 0x7F));
        state[33] = (byte)((byte)(state[33] << 7) | (byte)((state[34] >> 1) & 0x7F));
        state[34] = (byte)((byte)(state[34] << 7) | (byte)((state[35] >> 1) & 0x7F));
        state[35] = (byte)((byte)(state[35] << 7) | (byte)((tmp       >> 1) & 0x7F));
        tmp = state[36];
        state[36] = (byte)((byte)(state[36] << 7) | (byte)((state[37] >> 1) & 0x7F));
        state[37] = (byte)((byte)(state[37] << 7) | (byte)((state[38] >> 1) & 0x7F));
        state[38] = (byte)((byte)(state[38] << 7) | (byte)((state[39] >> 1) & 0x7F));
        state[39] = (byte)((byte)(state[39] << 7) | (byte)((tmp       >> 1) & 0x7F));
        tmp = state[40];
        state[40] = (byte)((byte)(state[40] << 7) | (byte)((state[41] >> 1) & 0x7F));
        state[41] = (byte)((byte)(state[41] << 7) | (byte)((state[42] >> 1) & 0x7F));
        state[42] = (byte)((byte)(state[42] << 7) | (byte)((state[43] >> 1) & 0x7F));
        state[43] = (byte)((byte)(state[43] << 7) | (byte)((tmp       >> 1) & 0x7F));
        tmp = state[44];
        state[44] = (byte)((byte)(state[44] << 7) | (byte)((state[45] >> 1) & 0x7F));
        state[45] = (byte)((byte)(state[45] << 7) | (byte)((state[46] >> 1) & 0x7F));
        state[46] = (byte)((byte)(state[46] << 7) | (byte)((state[47] >> 1) & 0x7F));
        state[47] = (byte)((byte)(state[47] << 7) | (byte)((tmp       >> 1) & 0x7F));
        
        //optimized
        Util.arrayCopyNonAtomic(state,   (short) 0, tempbuf, (short)  0, (short)  4);
        Util.arrayCopyNonAtomic(state,   (short) 4, state,   (short)  0, (short) 12);
        Util.arrayCopyNonAtomic(tempbuf, (short) 0, state,   (short) 12, (short)  4);
        
        // part 4
        xorMsg((byte)48, msgblk);
        xor((byte)48, (byte)16);
        andxor((byte)48, (byte)64, (byte)0);
        
        // rotate 22; block 48-63
        
        //rotate 2 bytes, word 1
        Util.arrayCopyNonAtomic(state,   (short) 48, tempbuf, (short)  0, (short)  2);
        Util.arrayCopyNonAtomic(state,   (short) 50, state,   (short) 48, (short)  2);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 50, (short)  2);
        //rotate 2 bytes, word 2
        Util.arrayCopyNonAtomic(state,   (short) 52, tempbuf, (short)  0, (short)  2);
        Util.arrayCopyNonAtomic(state,   (short) 54, state,   (short) 52, (short)  2);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 54, (short)  2);
        //rotate 2 bytes, word 3
        Util.arrayCopyNonAtomic(state,   (short) 56, tempbuf, (short)  0, (short)  2);
        Util.arrayCopyNonAtomic(state,   (short) 58, state,   (short) 56, (short)  2);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 58, (short)  2);
        //rotate 2 bytes, word 4
        Util.arrayCopyNonAtomic(state,   (short) 60, tempbuf, (short)  0, (short)  2);
        Util.arrayCopyNonAtomic(state,   (short) 62, state,   (short) 60, (short)  2);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 62, (short)  2);
        
        //we rotated 16 bits, now we rotate remaining 6
        
        tmp = state[48];
        state[48] = (byte)((byte)(state[48] << 6) | (byte)((state[49] >> 2) & 0x3F));
        state[49] = (byte)((byte)(state[49] << 6) | (byte)((state[50] >> 2) & 0x3F));
        state[50] = (byte)((byte)(state[50] << 6) | (byte)((state[51] >> 2) & 0x3F));
        state[51] = (byte)((byte)(state[51] << 6) | (byte)((tmp       >> 2) & 0x3F));
        tmp = state[52];
        state[52] = (byte)((byte)(state[52] << 6) | (byte)((state[53] >> 2) & 0x3F));
        state[53] = (byte)((byte)(state[53] << 6) | (byte)((state[54] >> 2) & 0x3F));
        state[54] = (byte)((byte)(state[54] << 6) | (byte)((state[55] >> 2) & 0x3F));
        state[55] = (byte)((byte)(state[55] << 6) | (byte)((tmp       >> 2) & 0x3F));
        tmp = state[56];
        state[56] = (byte)((byte)(state[56] << 6) | (byte)((state[57] >> 2) & 0x3F));
        state[57] = (byte)((byte)(state[57] << 6) | (byte)((state[58] >> 2) & 0x3F));
        state[58] = (byte)((byte)(state[58] << 6) | (byte)((state[59] >> 2) & 0x3F));
        state[59] = (byte)((byte)(state[59] << 6) | (byte)((tmp       >> 2) & 0x3F));
        tmp = state[60];
        state[60] = (byte)((byte)(state[60] << 6) | (byte)((state[61] >> 2) & 0x3F));
        state[61] = (byte)((byte)(state[61] << 6) | (byte)((state[62] >> 2) & 0x3F));
        state[62] = (byte)((byte)(state[62] << 6) | (byte)((state[63] >> 2) & 0x3F));
        state[63] = (byte)((byte)(state[63] << 6) | (byte)((tmp       >> 2) & 0x3F));
        
        // optimized
        Util.arrayCopyNonAtomic(state,   (short) 16, tempbuf, (short)  0, (short) 8);
        Util.arrayCopyNonAtomic(state,   (short) 24, state,   (short) 16, (short) 8);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 24, (short) 8);
        
        // part 5
        xorMsg((byte)64, msgblk);
        xor((byte)64, (byte)32);
        andxor((byte)64, (byte)0, (byte)16);
        
        // rotate 13, block 64-79
        
        //rotate 1 byte, word 1
        Util.arrayCopyNonAtomic(state,   (short) 64, tempbuf, (short)  0, (short)  1);
        Util.arrayCopyNonAtomic(state,   (short) 65, state,   (short) 64, (short)  3);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 67, (short)  1);
        //rotate 1 byte, word 2
        Util.arrayCopyNonAtomic(state,   (short) 68, tempbuf, (short)  0, (short)  1);
        Util.arrayCopyNonAtomic(state,   (short) 69, state,   (short) 68, (short)  3);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 71, (short)  1);
        //rotate 1 byte, word 3
        Util.arrayCopyNonAtomic(state,   (short) 72, tempbuf, (short)  0, (short)  1);
        Util.arrayCopyNonAtomic(state,   (short) 73, state,   (short) 72, (short)  3);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 75, (short)  1);
        //rotate 1 byte, word 4
        Util.arrayCopyNonAtomic(state,   (short) 76, tempbuf, (short)  0, (short)  1);
        Util.arrayCopyNonAtomic(state,   (short) 77, state,   (short) 76, (short)  3);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state,   (short) 79, (short)  1);
        
        //we rotated 8 bits, now we rotate remaining 5
        
        tmp = state[64];
        state[64] = (byte)((byte)(state[64] << 5) | (byte)((state[65] >> 3) & 0x1F));
        state[65] = (byte)((byte)(state[65] << 5) | (byte)((state[66] >> 3) & 0x1F));
        state[66] = (byte)((byte)(state[66] << 5) | (byte)((state[67] >> 3) & 0x1F));
        state[67] = (byte)((byte)(state[67] << 5) | (byte)((tmp       >> 3) & 0x1F));
        tmp = state[68];
        state[68] = (byte)((byte)(state[68] << 5) | (byte)((state[69] >> 3) & 0x1F));
        state[69] = (byte)((byte)(state[69] << 5) | (byte)((state[70] >> 3) & 0x1F));
        state[70] = (byte)((byte)(state[70] << 5) | (byte)((state[71] >> 3) & 0x1F));
        state[71] = (byte)((byte)(state[71] << 5) | (byte)((tmp       >> 3) & 0x1F));
        tmp = state[72];
        state[72] = (byte)((byte)(state[72] << 5) | (byte)((state[73] >> 3) & 0x1F));
        state[73] = (byte)((byte)(state[73] << 5) | (byte)((state[74] >> 3) & 0x1F));
        state[74] = (byte)((byte)(state[74] << 5) | (byte)((state[75] >> 3) & 0x1F));
        state[75] = (byte)((byte)(state[75] << 5) | (byte)((tmp       >> 3) & 0x1F));
        tmp = state[76];
        state[76] = (byte)((byte)(state[76] << 5) | (byte)((state[77] >> 3) & 0x1F));
        state[77] = (byte)((byte)(state[77] << 5) | (byte)((state[78] >> 3) & 0x1F));
        state[78] = (byte)((byte)(state[78] << 5) | (byte)((state[79] >> 3) & 0x1F));
        state[79] = (byte)((byte)(state[79] << 5) | (byte)((tmp       >> 3) & 0x1F));
        
        // optimized
        Util.arrayCopyNonAtomic(state,   (short) 32, tempbuf, (short)  0, (short) 16);
        Util.arrayCopyNonAtomic(tempbuf, (short) 12, state,   (short) 32, (short)  4);
        Util.arrayCopyNonAtomic(tempbuf, (short)  0, state, (short)   36, (short) 12);
    }
  
    void morus_initialization(){
        byte[] temp = { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 };
        byte[] con0 = {(byte)0x00,(byte)0x01,(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x05,(byte)0x08,(byte)0x0d,(byte)0x15,(byte)0x22,(byte)0x37,(byte)0x59,(byte)0x90,(byte)0xe9,(byte)0x79,(byte)0x62};
        byte[] con1 = {(byte)0xdb, (byte)0x3d, (byte)0x18, (byte)0x55, (byte)0x6d, (byte)0xc2, (byte)0x2f, (byte)0xf1, (byte)0x20, (byte)0x11, (byte)0x31, (byte)0x42, (byte)0x73, (byte)0xb5, (byte)0x28, (byte)0xdd};
        
        Util.arrayCopyNonAtomic(npub, (short)0, state, (short)0, (short)16);
        Util.arrayCopyNonAtomic(k, (short)0, state, (short)16, (short)16);
        Util.arrayFillNonAtomic(state, (short)32, (short)16, (byte)0xff);
        Util.arrayCopyNonAtomic(con0, (short)0, state, (short)48, (short)16);
        Util.arrayCopyNonAtomic(con1, (short)0, state, (short)64, (short)16);
        Util.arrayFillNonAtomic(temp, (short)0, (short)16, (byte)0x00);
        
        // change state endianness
        for(byte i=0; i<80; i=(byte)(i+4)){
            if(i<16 || i>=32){
                temp1 = state[i];
                state[i] = state[(byte)(i+3)];
                state[(byte)(i+3)] = temp1;
                temp1 = state[(byte)(i+1)];
                state[(byte)(i+1)] = state[(byte)(i+2)];
                state[(byte)(i+2)] = temp1;
            }
        }
        
        for(short i=0; i<16; i++)
            morus_stateupdate(temp); // BOTTLENECK
        for(short i=0; i<16; i++)
            state[(byte)(i+16)] ^= k[i];
    }   
    
    void morus_enc_auth_step() {
        ciphertextblock[0]  = (byte)(plaintextblock[0]  ^ state[0]  ^ state[20] ^ (byte)(state[32] & state[48]));
        ciphertextblock[4]  = (byte)(plaintextblock[4]  ^ state[4]  ^ state[24] ^ (byte)(state[36] & state[52]));
        ciphertextblock[8]  = (byte)(plaintextblock[8]  ^ state[8]  ^ state[28] ^ (byte)(state[40] & state[56]));
        ciphertextblock[12] = (byte)(plaintextblock[12] ^ state[12] ^ state[16] ^ (byte)(state[44] & state[60]));

        ciphertextblock[1]  = (byte)(plaintextblock[1]  ^ state[1]  ^ state[21] ^ (byte)(state[33] & state[49]));
        ciphertextblock[5]  = (byte)(plaintextblock[5]  ^ state[5]  ^ state[25] ^ (byte)(state[37] & state[53]));
        ciphertextblock[9]  = (byte)(plaintextblock[9]  ^ state[9]  ^ state[29] ^ (byte)(state[41] & state[57]));
        ciphertextblock[13] = (byte)(plaintextblock[13] ^ state[13] ^ state[17] ^ (byte)(state[45] & state[61]));

        ciphertextblock[2]  = (byte)(plaintextblock[2]  ^ state[2]  ^ state[22] ^ (byte)(state[34] & state[50]));
        ciphertextblock[6]  = (byte)(plaintextblock[6]  ^ state[6]  ^ state[26] ^ (byte)(state[38] & state[54]));
        ciphertextblock[10] = (byte)(plaintextblock[10] ^ state[10] ^ state[30] ^ (byte)(state[42] & state[58]));
        ciphertextblock[14] = (byte)(plaintextblock[14] ^ state[14] ^ state[18] ^ (byte)(state[46] & state[62]));

        ciphertextblock[3]  = (byte)(plaintextblock[3]  ^ state[3]  ^ state[23] ^ (byte)(state[35] & state[51]));
        ciphertextblock[7]  = (byte)(plaintextblock[7]  ^ state[7]  ^ state[27] ^ (byte)(state[39] & state[55]));
        ciphertextblock[11] = (byte)(plaintextblock[11] ^ state[11] ^ state[31] ^ (byte)(state[43] & state[59]));
        ciphertextblock[15] = (byte)(plaintextblock[15] ^ state[15] ^ state[19] ^ (byte)(state[47] & state[63]));
            
        morus_stateupdate(plaintextblock);
    }
    
    void morus_dec_auth_step() {
        plaintextblock[0]  = (byte)(ciphertextblock[0]  ^ state[0]  ^ state[20] ^ (byte)(state[32] & state[48]));
        plaintextblock[4]  = (byte)(ciphertextblock[4]  ^ state[4]  ^ state[24] ^ (byte)(state[36] & state[52]));
        plaintextblock[8]  = (byte)(ciphertextblock[8]  ^ state[8]  ^ state[28] ^ (byte)(state[40] & state[56]));
        plaintextblock[12] = (byte)(ciphertextblock[12] ^ state[12] ^ state[16] ^ (byte)(state[44] & state[60]));
        
        plaintextblock[1]  = (byte)(ciphertextblock[1]  ^ state[1]  ^ state[21] ^ (byte)(state[33] & state[49]));
        plaintextblock[5]  = (byte)(ciphertextblock[5]  ^ state[5]  ^ state[25] ^ (byte)(state[37] & state[53]));
        plaintextblock[9]  = (byte)(ciphertextblock[9]  ^ state[9]  ^ state[29] ^ (byte)(state[41] & state[57]));
        plaintextblock[13] = (byte)(ciphertextblock[13] ^ state[13] ^ state[17] ^ (byte)(state[45] & state[61]));

        plaintextblock[2]  = (byte)(ciphertextblock[2]  ^ state[2]  ^ state[22] ^ (byte)(state[34] & state[50]));
        plaintextblock[6]  = (byte)(ciphertextblock[6]  ^ state[6]  ^ state[26] ^ (byte)(state[38] & state[54]));
        plaintextblock[10] = (byte)(ciphertextblock[10] ^ state[10] ^ state[30] ^ (byte)(state[42] & state[58]));
        plaintextblock[14] = (byte)(ciphertextblock[14] ^ state[14] ^ state[18] ^ (byte)(state[46] & state[62]));

        plaintextblock[3]  = (byte)(ciphertextblock[3]  ^ state[3]  ^ state[23] ^ (byte)(state[35] & state[51]));
        plaintextblock[7]  = (byte)(ciphertextblock[7]  ^ state[7]  ^ state[27] ^ (byte)(state[39] & state[55]));
        plaintextblock[11] = (byte)(ciphertextblock[11] ^ state[11] ^ state[31] ^ (byte)(state[43] & state[59]));
        plaintextblock[15] = (byte)(ciphertextblock[15] ^ state[15] ^ state[19] ^ (byte)(state[47] & state[63]));
        
        morus_stateupdate(plaintextblock);
    }
    
    void morus_tag_generation() {
        Util.arrayCopyNonAtomic(state, (short)48, tempbuf, (short)0, (short)16);
        Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0x00);
        Util.arrayFillNonAtomic(ciphertextblock, (short)0, (short)16, (byte)0x00);
        Util.setShort(plaintextblock, (byte)2, (short)(adlen<<3));
        Util.setShort(ciphertextblock, (byte)2, (short)(mlen<<3));
        for(byte i=0; i<8; i++){
            tempbuf[i] ^= plaintextblock[i];
            tempbuf[(byte)(i+8)] ^= ciphertextblock[i];
        }
        Util.arrayCopyNonAtomic(tempbuf, (short)0, plaintextblock, (short)0, (short)16);
        
        xor((byte)64, (byte)0);
        
        // update state 8 times
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        
        for (byte i = 2; i < 5; i++) {
        for (byte j = 0; j < 4; j++) { 
            state[(byte)(16+(byte)(4*j))] ^= state[(byte)((byte)(16*i)+(byte)(4*j))];
            state[(byte)(16+(byte)(4*j)+1)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+1))];
            state[(byte)(16+(byte)(4*j)+2)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+2))];
            state[(byte)(16+(byte)(4*j)+3)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+3))];
        }}
        // copy the tag at the end of cipher
        Util.arrayCopyNonAtomic(state, (short)16, c, mlen, (short)16);
    }
    
    byte morus_tag_verification() {
        Util.arrayCopyNonAtomic(state, (short)48, tempbuf, (short)0, (short)16);
        Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0x00);
        Util.arrayFillNonAtomic(ciphertextblock, (short)0, (short)16, (byte)0x00);
        Util.setShort(plaintextblock, (byte)2, (short)(adlen<<3));
        Util.setShort(ciphertextblock, (byte)2, (short)(mlen<<3));
        for(byte i=0; i<8; i++){
            tempbuf[i] ^= plaintextblock[i];
            tempbuf[(byte)(i+8)] ^= ciphertextblock[i];
        }
        Util.arrayCopyNonAtomic(tempbuf, (short)0, plaintextblock, (short)0, (short)16);
        
        xor((byte)64, (byte)0);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        morus_stateupdate(plaintextblock);
        
        for (byte i = 2; i < 5; i++) {
        for (byte j = 0; j < 4; j++) { 
            state[(byte)(16+(byte)(4*j))] ^= state[(byte)((byte)(16*i)+(byte)(4*j))];
            state[(byte)(16+(byte)(4*j)+1)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+1))];
            state[(byte)(16+(byte)(4*j)+2)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+2))];
            state[(byte)(16+(byte)(4*j)+3)] ^= state[(byte)((byte)(16*i)+(byte)((byte)(4*j)+3))];
        }}
        // verify the tag (calculated tag is in state[16:31] & stored tag is in c[clen-16:clen]
        temp1 = 0;
        Util.arrayCopyNonAtomic(c, (short)(clen-16), plaintextblock, (short)0, (short)16);
        for (byte i = 0; i < 1; i++){
            //System.out.println(bytesToHex(plaintextblock));
            temp1 |=  (byte)( plaintextblock[i] ^ state[(byte)(16+i)] );
        }
        if (temp1 == (byte)0) return (byte)0; 
        else return (byte)-1;
    }
    
    public byte encrypt(byte[] cipher,   short cipherlen,
                        byte[] message,  short messagelen,
                        byte[] authdata, short authdatalen) {
        
        // change endianness of authdata
        changeEndianness((short)0, authdatalen, authdata);
        ad = authdata;
        adlen = authdatalen;

        c = cipher;
        clen = cipherlen;

        // change endiannesss of message
        changeEndianness((short)0, messagelen, message);
        m = message;
        mlen = messagelen;
             
        short i;
        // process the associated data
        for (i = 0; (short) (i+16) <= adlen; i += 16) {
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)16);
            morus_enc_auth_step();
        }
        if (  (adlen%16) != 0 )  {
            Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)(adlen%16));
            morus_enc_auth_step();
        }
        
        // encrypt the plaintext
        short j;
        for (j = 0; (short)(j+16) <= mlen; j += 16) {
            Util.arrayCopyNonAtomic(m, j, plaintextblock, (short)0, (short)16);
            morus_enc_auth_step();
            Util.arrayCopyNonAtomic(ciphertextblock, (short)0, c, j, (short)16);
        }
        if (  (mlen%16) != 0 )  {
            Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(m, j, plaintextblock, (short)0, (short)(mlen%16));
            morus_enc_auth_step();
            Util.arrayCopyNonAtomic(ciphertextblock, (short)0, c, j, (short)(mlen%16));
        }
        
        morus_tag_generation();
        
        return (byte)0;
    }
    
    public byte decrypt(byte[] cipher,   short cipherlen,
                        byte[] message,  short messagelen,
                        byte[] authdata, short authdatalen) {
        
        if (cipherlen < 16) return -1;    
        
        c = cipher;
        clen = cipherlen;
        
        //messagelen is usually 0 at decrypt
        m = message;
        mlen = messagelen;
        
        // change endianness of authdata
        changeEndianness((short)0, authdatalen, authdata);
        ad = authdata;
        adlen = authdatalen;
        
        short i;
        
        // process the associated data
        for (i = 0; (short)(i+16) <= adlen; i += 16) {
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)16);
            morus_enc_auth_step();
        }
        if (  (adlen%16) != 0 )  {
            Util.arrayFillNonAtomic(plaintextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(ad, i, plaintextblock, (short)0, (short)(adlen%16));
            morus_enc_auth_step();
        }
        
        // decrypt the ciphertext
        short j;
        for (j = 0; (short)(j+16) <= (short)(clen-16); j += 16) {
            Util.arrayCopyNonAtomic(c, j, ciphertextblock, (short)0, (short)16);
            morus_dec_auth_step();
            Util.arrayCopyNonAtomic(plaintextblock, (short)0, m, j, (short)16);
        }
        if (  (clen%16) != 0 )  {
            Util.arrayFillNonAtomic(ciphertextblock, (short)0, (short)16, (byte)0);
            Util.arrayCopyNonAtomic(c, j, ciphertextblock, (short)0, (short)(clen%16));
            morus_dec_auth_step();
            Util.arrayCopyNonAtomic(plaintextblock, (short)0, m, j, (short)(clen%16));
        }
        changeEndianness((short)0, (short)(clen-16), m);
        
        // tag verification
        return morus_tag_verification();
    }
    
}
