package applets;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 * @optimized Matej Evin
 * 17 September 2018
 * transcribed from C version of Zorro:
 * https://github.com/nablahero/zorro_c/blob/master/zorro.c
 */

public class ZorroCipher extends Cipher implements IConsts
{
	
	private  final byte [] s = {
		(byte) 0xB2, (byte) 0xE5, (byte) 0x5E, (byte) 0xFD, (byte) 0x5F, (byte) 0xC5, (byte) 0x50, (byte) 0xBC, (byte) 0xDC, (byte) 0x4A, (byte) 0xFA, (byte) 0x88, (byte) 0x28, (byte) 0xD8, (byte) 0xE0, (byte) 0xD1,
		(byte) 0xB5, (byte) 0xD0, (byte) 0x3C, (byte) 0xB0, (byte) 0x99, (byte) 0xC1, (byte) 0xE8, (byte) 0xE2, (byte) 0x13, (byte) 0x59, (byte) 0xA7, (byte) 0xFB, (byte) 0x71, (byte) 0x34, (byte) 0x31, (byte) 0xF1,
		(byte) 0x9F, (byte) 0x3A, (byte) 0xCE, (byte) 0x6E, (byte) 0xA8, (byte) 0xA4, (byte) 0xB4, (byte) 0x7E, (byte) 0x1F, (byte) 0xB7, (byte) 0x51, (byte) 0x1D, (byte) 0x38, (byte) 0x9D, (byte) 0x46, (byte) 0x69,
		(byte) 0x53, (byte) 0x0E, (byte) 0x42, (byte) 0x1B, (byte) 0x0F, (byte) 0x11, (byte) 0x68, (byte) 0xCA, (byte) 0xAA, (byte) 0x06, (byte) 0xF0, (byte) 0xBD, (byte) 0x26, (byte) 0x6F, (byte) 0x00, (byte) 0xD9,
		(byte) 0x62, (byte) 0xF3, (byte) 0x15, (byte) 0x60, (byte) 0xF2, (byte) 0x3D, (byte) 0x7F, (byte) 0x35, (byte) 0x63, (byte) 0x2D, (byte) 0x67, (byte) 0x93, (byte) 0x1C, (byte) 0x91, (byte) 0xF9, (byte) 0x9C,
		(byte) 0x66, (byte) 0x2A, (byte) 0x81, (byte) 0x20, (byte) 0x95, (byte) 0xF8, (byte) 0xE3, (byte) 0x4D, (byte) 0x5A, (byte) 0x6D, (byte) 0x24, (byte) 0x7B, (byte) 0xB9, (byte) 0xEF, (byte) 0xDF, (byte) 0xDA,
		(byte) 0x58, (byte) 0xA9, (byte) 0x92, (byte) 0x76, (byte) 0x2E, (byte) 0xB3, (byte) 0x39, (byte) 0x0C, (byte) 0x29, (byte) 0xCD, (byte) 0x43, (byte) 0xFE, (byte) 0xAB, (byte) 0xF5, (byte) 0x94, (byte) 0x23,
		(byte) 0x16, (byte) 0x80, (byte) 0xC0, (byte) 0x12, (byte) 0x4C, (byte) 0xE9, (byte) 0x48, (byte) 0x19, (byte) 0x08, (byte) 0xAE, (byte) 0x41, (byte) 0x70, (byte) 0x84, (byte) 0x14, (byte) 0xA2, (byte) 0xD5,
		(byte) 0xB8, (byte) 0x33, (byte) 0x65, (byte) 0xBA, (byte) 0xED, (byte) 0x17, (byte) 0xCF, (byte) 0x96, (byte) 0x1E, (byte) 0x3B, (byte) 0x0B, (byte) 0xC2, (byte) 0xC8, (byte) 0xB6, (byte) 0xBB, (byte) 0x8B,
		(byte) 0xA1, (byte) 0x54, (byte) 0x75, (byte) 0xC4, (byte) 0x10, (byte) 0x5D, (byte) 0xD6, (byte) 0x25, (byte) 0x97, (byte) 0xE6, (byte) 0xFC, (byte) 0x49, (byte) 0xF7, (byte) 0x52, (byte) 0x18, (byte) 0x86,
		(byte) 0x8D, (byte) 0xCB, (byte) 0xE1, (byte) 0xBF, (byte) 0xD7, (byte) 0x8E, (byte) 0x37, (byte) 0xBE, (byte) 0x82, (byte) 0xCC, (byte) 0x64, (byte) 0x90, (byte) 0x7C, (byte) 0x32, (byte) 0x8F, (byte) 0x4B,
		(byte) 0xAC, (byte) 0x1A, (byte) 0xEA, (byte) 0xD3, (byte) 0xF4, (byte) 0x6B, (byte) 0x2C, (byte) 0xFF, (byte) 0x55, (byte) 0x0A, (byte) 0x45, (byte) 0x09, (byte) 0x89, (byte) 0x01, (byte) 0x30, (byte) 0x2B,
		(byte) 0xD2, (byte) 0x77, (byte) 0x87, (byte) 0x72, (byte) 0xEB, (byte) 0x36, (byte) 0xDE, (byte) 0x9E, (byte) 0x8C, (byte) 0xDB, (byte) 0x6C, (byte) 0x9B, (byte) 0x05, (byte) 0x02, (byte) 0x4E, (byte) 0xAF,
		(byte) 0x04, (byte) 0xAD, (byte) 0x74, (byte) 0xC3, (byte) 0xEE, (byte) 0xA6, (byte) 0xF6, (byte) 0xC7, (byte) 0x7D, (byte) 0x40, (byte) 0xD4, (byte) 0x0D, (byte) 0x3E, (byte) 0x5B, (byte) 0xEC, (byte) 0x78,
		(byte) 0xA0, (byte) 0xB1, (byte) 0x44, (byte) 0x73, (byte) 0x47, (byte) 0x5C, (byte) 0x98, (byte) 0x21, (byte) 0x22, (byte) 0x61, (byte) 0x3F, (byte) 0xC6, (byte) 0x7A, (byte) 0x56, (byte) 0xDD, (byte) 0xE7,
		(byte) 0x85, (byte) 0xC9, (byte) 0x8A, (byte) 0x57, (byte) 0x27, (byte) 0x07, (byte) 0x9A, (byte) 0x03, (byte) 0xA3, (byte) 0x83, (byte) 0xE4, (byte) 0x6A, (byte) 0xA5, (byte) 0x2F, (byte) 0x79, (byte) 0x4F
	};
	
	private  final byte [] inv_s = {
        (byte) 0x3E, (byte) 0xBD, (byte) 0xCD, (byte) 0xF7, (byte) 0xD0, (byte) 0xCC, (byte) 0x39, (byte) 0xF5, (byte) 0x78, (byte) 0xBB, (byte) 0xB9, (byte) 0x8A, (byte) 0x67, (byte) 0xDB, (byte) 0x31, (byte) 0x34,
        (byte) 0x94, (byte) 0x35, (byte) 0x73, (byte) 0x18, (byte) 0x7D, (byte) 0x42, (byte) 0x70, (byte) 0x85, (byte) 0x9E, (byte) 0x77, (byte) 0xB1, (byte) 0x33, (byte) 0x4C, (byte) 0x2B, (byte) 0x88, (byte) 0x28,
        (byte) 0x53, (byte) 0xE7, (byte) 0xE8, (byte) 0x6F, (byte) 0x5A, (byte) 0x97, (byte) 0x3C, (byte) 0xF4, (byte) 0x0C, (byte) 0x68, (byte) 0x51, (byte) 0xBF, (byte) 0xB6, (byte) 0x49, (byte) 0x64, (byte) 0xFD,
        (byte) 0xBE, (byte) 0x1E, (byte) 0xAD, (byte) 0x81, (byte) 0x1D, (byte) 0x47, (byte) 0xC5, (byte) 0xA6, (byte) 0x2C, (byte) 0x66, (byte) 0x21, (byte) 0x89, (byte) 0x12, (byte) 0x45, (byte) 0xDC, (byte) 0xEA,
        (byte) 0xD9, (byte) 0x7A, (byte) 0x32, (byte) 0x6A, (byte) 0xE2, (byte) 0xBA, (byte) 0x2E, (byte) 0xE4, (byte) 0x76, (byte) 0x9B, (byte) 0x09, (byte) 0xAF, (byte) 0x74, (byte) 0x57, (byte) 0xCE, (byte) 0xFF,
        (byte) 0x06, (byte) 0x2A, (byte) 0x9D, (byte) 0x30, (byte) 0x91, (byte) 0xB8, (byte) 0xED, (byte) 0xF3, (byte) 0x60, (byte) 0x19, (byte) 0x58, (byte) 0xDD, (byte) 0xE5, (byte) 0x95, (byte) 0x02, (byte) 0x04,
        (byte) 0x43, (byte) 0xE9, (byte) 0x40, (byte) 0x48, (byte) 0xAA, (byte) 0x82, (byte) 0x50, (byte) 0x4A, (byte) 0x36, (byte) 0x2F, (byte) 0xFB, (byte) 0xB5, (byte) 0xCA, (byte) 0x59, (byte) 0x23, (byte) 0x3D,
        (byte) 0x7B, (byte) 0x1C, (byte) 0xC3, (byte) 0xE3, (byte) 0xD2, (byte) 0x92, (byte) 0x63, (byte) 0xC1, (byte) 0xDF, (byte) 0xFE, (byte) 0xEC, (byte) 0x5B, (byte) 0xAC, (byte) 0xD8, (byte) 0x27, (byte) 0x46,
        (byte) 0x71, (byte) 0x52, (byte) 0xA8, (byte) 0xF9, (byte) 0x7C, (byte) 0xF0, (byte) 0x9F, (byte) 0xC2, (byte) 0x0B, (byte) 0xBC, (byte) 0xF2, (byte) 0x8F, (byte) 0xC8, (byte) 0xA0, (byte) 0xA5, (byte) 0xAE,
        (byte) 0xAB, (byte) 0x4D, (byte) 0x62, (byte) 0x4B, (byte) 0x6E, (byte) 0x54, (byte) 0x87, (byte) 0x98, (byte) 0xE6, (byte) 0x14, (byte) 0xF6, (byte) 0xCB, (byte) 0x4F, (byte) 0x2D, (byte) 0xC7, (byte) 0x20,
        (byte) 0xE0, (byte) 0x90, (byte) 0x7E, (byte) 0xF8, (byte) 0x25, (byte) 0xFC, (byte) 0xD5, (byte) 0x1A, (byte) 0x24, (byte) 0x61, (byte) 0x38, (byte) 0x6C, (byte) 0xB0, (byte) 0xD1, (byte) 0x79, (byte) 0xCF,
        (byte) 0x13, (byte) 0xE1, (byte) 0x00, (byte) 0x65, (byte) 0x26, (byte) 0x10, (byte) 0x8D, (byte) 0x29, (byte) 0x80, (byte) 0x5C, (byte) 0x83, (byte) 0x8E, (byte) 0x07, (byte) 0x3B, (byte) 0xA7, (byte) 0xA3,
        (byte) 0x72, (byte) 0x15, (byte) 0x8B, (byte) 0xD3, (byte) 0x93, (byte) 0x05, (byte) 0xEB, (byte) 0xD7, (byte) 0x8C, (byte) 0xF1, (byte) 0x37, (byte) 0xA1, (byte) 0xA9, (byte) 0x69, (byte) 0x22, (byte) 0x86,
        (byte) 0x11, (byte) 0x0F, (byte) 0xC0, (byte) 0xB3, (byte) 0xDA, (byte) 0x7F, (byte) 0x96, (byte) 0xA4, (byte) 0x0D, (byte) 0x3F, (byte) 0x5F, (byte) 0xC9, (byte) 0x08, (byte) 0xEE, (byte) 0xC6, (byte) 0x5E,
        (byte) 0x0E, (byte) 0xA2, (byte) 0x17, (byte) 0x56, (byte) 0xFA, (byte) 0x01, (byte) 0x99, (byte) 0xEF, (byte) 0x16, (byte) 0x75, (byte) 0xB2, (byte) 0xC4, (byte) 0xDE, (byte) 0x84, (byte) 0xD4, (byte) 0x5D,
        (byte) 0x3A, (byte) 0x1F, (byte) 0x44, (byte) 0x41, (byte) 0xB4, (byte) 0x6D, (byte) 0xD6, (byte) 0x9C, (byte) 0x55, (byte) 0x4E, (byte) 0x0A, (byte) 0x1B, (byte) 0x9A, (byte) 0x03, (byte) 0x6B, (byte) 0xB7
	};
    
    // Constants
	public static final byte  ALG_ZORRO                     = (byte)   18; // ID of ZORRO cipher
	public static final byte  LENGTH_ZORRO                  = (byte)  128; // Block length size
	public static final short TEMP_LENGTH                   = (short)  40;
    
    // Key storage (why DES?)
	private DESKey cipherKey;
    
    // Variables
	private byte    mode; // encrypt/decrypt
	private static  ZorroCipher m_instance = null;  //instance of cipher itself
	//private boolean externalAccess;                 //probably useless?
	private boolean isInitialized = false;          //
	
    // Arrays
	private byte[] temp = JCSystem.makeTransientByteArray(TEMP_LENGTH, JCSystem.CLEAR_ON_DESELECT); //16 bytes state, 16 bytes key, 8 bytes aux memory

    // Empty constructor
	protected ZorroCipher()	{}
    
    //multiplication over Galois Field 2_8
	private byte mGF(byte a, byte b) {
        
        byte p = 0;
		byte bit_set;
		byte i = 0;
		
		for(i = 0; i < 8; i++)
		{
			if ((b & 1) == 1)
				p ^= a;
			bit_set = (byte) (a & 0x80);
			a <<= 1;
			if (bit_set == (byte)(0x80))
				a ^= 0x1b; // This is Rijndael polynomial
			b >>= 1;
		}
		return p;
	}
	
    //Mix Columns in one row, unrolled loop
	private void mixColumn(byte[] column, short offset) {
        
        //save columns into temporary
		temp[36] = column[             offset ]; temp[37] = column[(short) (1 + offset)];
        temp[38] = column[(short) (2 + offset)]; temp[39] = column[(short) (3 + offset)];
        
        //update columns
		column[             offset ] = (byte) (mGF(temp[36], (byte) 2) ^ mGF(temp[37], (byte) 3) ^ mGF(temp[38], (byte) 1) ^ mGF(temp[39], (byte) 1));
		column[(short) (1 + offset)] = (byte) (mGF(temp[36], (byte) 1) ^ mGF(temp[37], (byte) 2) ^ mGF(temp[38], (byte) 3) ^ mGF(temp[39], (byte) 1));
		column[(short) (2 + offset)] = (byte) (mGF(temp[36], (byte) 1) ^ mGF(temp[37], (byte) 1) ^ mGF(temp[38], (byte) 2) ^ mGF(temp[39], (byte) 3));
		column[(short) (3 + offset)] = (byte) (mGF(temp[36], (byte) 3) ^ mGF(temp[37], (byte) 1) ^ mGF(temp[38], (byte) 1) ^ mGF(temp[39], (byte) 2));
	}
    
    //Inverse Mix Columns in one row, unrolled loop
	private void invMixColumn(byte[] column, short offset) {
        
        //save columns into temporary
		temp[36] = column[             offset ]; temp[37] = column[(short) (1 + offset)];
        temp[38] = column[(short) (2 + offset)]; temp[39] = column[(short) (3 + offset)];
        
        //update columns
		column[             offset ] = (byte) (mGF(temp[36], (byte) 14) ^ mGF(temp[37], (byte) 11) ^ mGF(temp[38], (byte) 13) ^ mGF(temp[39], (byte)  9));
		column[(short) (1 + offset)] = (byte) (mGF(temp[36], (byte)  9) ^ mGF(temp[37], (byte) 14) ^ mGF(temp[38], (byte) 11) ^ mGF(temp[39], (byte) 13));
		column[(short) (2 + offset)] = (byte) (mGF(temp[36], (byte) 13) ^ mGF(temp[37], (byte)  9) ^ mGF(temp[38], (byte) 14) ^ mGF(temp[39], (byte) 11));
		column[(short) (3 + offset)] = (byte) (mGF(temp[36], (byte) 11) ^ mGF(temp[37], (byte) 13) ^ mGF(temp[38], (byte)  9) ^ mGF(temp[39], (byte) 14));
	}
    
    //Mix Columns in state, unrolled loops
    //why is mixcolumn done in temp buffer and not in the intern buffer directly? Should intern buffer be preserved?
    private void zorro_MixColumns(byte[] internBuffer, short offset) {
		
        // 4 undrolled iterations - copy to temp, mix in temp, copy from temp
        //temp uses indexes 32, 33, 34, 35
        temp[32] = internBuffer[              offset ]; temp[33] = internBuffer[(short) (1  + offset)];
        temp[34] = internBuffer[(short) (2  + offset)]; temp[35] = internBuffer[(short) (3  + offset)];
        mixColumn(temp, (byte) 32);
        internBuffer[              offset ] = temp[32]; internBuffer[(short) (1  + offset)] = temp[33];
        internBuffer[(short) (2  + offset)] = temp[34]; internBuffer[(short) (3  + offset)] = temp[35];
        
        temp[32] = internBuffer[(short) (4  + offset)]; temp[33] = internBuffer[(short) (5  + offset)];
        temp[34] = internBuffer[(short) (6  + offset)]; temp[35] = internBuffer[(short) (7  + offset)];
        mixColumn(temp, 32);
        internBuffer[(short) (4  + offset)] = temp[32]; internBuffer[(short) (5  + offset)] = temp[33];
        internBuffer[(short) (6  + offset)] = temp[34]; internBuffer[(short) (7  + offset)] = temp[35];
        
        temp[32] = internBuffer[(short) (8  + offset)]; temp[33] = internBuffer[(short) (9  + offset)];
        temp[34] = internBuffer[(short) (10 + offset)]; temp[35] = internBuffer[(short) (11 + offset)];
        mixColumn(temp, 32);
        internBuffer[(short) (8  + offset)] = temp[32]; internBuffer[(short) (9  + offset)] = temp[33];
        internBuffer[(short) (10 + offset)] = temp[34]; internBuffer[(short) (11 + offset)] = temp[35];
        
        temp[32] = internBuffer[(short) (12 + offset)]; temp[33] = internBuffer[(short) (13 + offset)];
        temp[34] = internBuffer[(short) (14 + offset)]; temp[35] = internBuffer[(short) (15 + offset)];
        mixColumn(temp, 32);
        internBuffer[(short) (12 + offset)] = temp[32]; internBuffer[(short) (13 + offset)] = temp[33];
        internBuffer[(short) (14 + offset)] = temp[34]; internBuffer[(short) (15 + offset)] = temp[35];
    }
   
    //Inverse Mix Columns in state, unrolled loops
    //why is mixcolumn done in temp buffer and not in the intern buffer directly? Should intern buffer be preserved?
	private void zorro_InvMixColumns(byte[] internBuffer, short offset) {
        
        // 4 undrolled iterations - copy to temp, mix in temp, copy from temp
        //temp uses indexes 32, 33, 34, 35
        temp[32] = internBuffer[              offset ]; temp[33] = internBuffer[(short) (1  + offset)];
        temp[34] = internBuffer[(short) (2  + offset)]; temp[35] = internBuffer[(short) (3  + offset)];
        invMixColumn(temp, 32);
        internBuffer[              offset ] = temp[32]; internBuffer[(short) (1  + offset)] = temp[33];
        internBuffer[(short) (2  + offset)] = temp[34]; internBuffer[(short) (3  + offset)] = temp[35];
        
        temp[32] = internBuffer[(short) (4  + offset)]; temp[33] = internBuffer[(short) (5  + offset)];
        temp[34] = internBuffer[(short) (6  + offset)]; temp[35] = internBuffer[(short) (7  + offset)];
        invMixColumn(temp, 32);
        internBuffer[(short) (4  + offset)] = temp[32]; internBuffer[(short) (5  + offset)] = temp[33];
        internBuffer[(short) (6  + offset)] = temp[34]; internBuffer[(short) (7  + offset)] = temp[35];
        
        temp[32] = internBuffer[(short) (8  + offset)]; temp[33] = internBuffer[(short) (9  + offset)];
        temp[34] = internBuffer[(short) (10 + offset)]; temp[35] = internBuffer[(short) (11 + offset)];
        invMixColumn(temp, 32);
        internBuffer[(short) (8  + offset)] = temp[32]; internBuffer[(short) (9  + offset)] = temp[33];
        internBuffer[(short) (10 + offset)] = temp[34]; internBuffer[(short) (11 + offset)] = temp[35];
        
        temp[32] = internBuffer[(short) (12 + offset)]; temp[33] = internBuffer[(short) (13 + offset)];
        temp[34] = internBuffer[(short) (14 + offset)]; temp[35] = internBuffer[(short) (15 + offset)];
        invMixColumn(temp, 32);
        internBuffer[(short) (12 + offset)] = temp[32]; internBuffer[(short) (13 + offset)] = temp[33];
        internBuffer[(short) (14 + offset)] = temp[34]; internBuffer[(short) (15 + offset)] = temp[35];
	}
	
    //one round of encryption
    //I really don't think the bitwise magic is necessary
	private void zorroOneRoundEnc(byte[] state, short offset, byte round) {
        
        byte tmp;
        
        //Sub Bytes
		state[(short) ( 0 + offset)] = s[(short) (state[(short) ( 0 + offset)] & 0x00ff)];
		state[(short) ( 4 + offset)] = s[(short) (state[(short) ( 4 + offset)] & 0x00ff)];
		state[(short) ( 8 + offset)] = s[(short) (state[(short) ( 8 + offset)] & 0x00ff)];
		state[(short) (12 + offset)] = s[(short) (state[(short) (12 + offset)] & 0x00ff)];
        
		//Add Constant
		state[(short) ( 0 + offset)] = (byte) (state[(short) ( 0 + offset)] ^  round);
		state[(short) ( 4 + offset)] = (byte) (state[(short) ( 4 + offset)] ^  round);
		state[(short) ( 8 + offset)] = (byte) (state[(short) ( 8 + offset)] ^  round);
		state[(short) (12 + offset)] = (byte) (state[(short) (12 + offset)] ^ (round << 3));
		
		//Shift Rows
		tmp = state[(short) (1 + offset)];
		state[(short) ( 1 + offset)] = state[(short) ( 5 + offset)];
		state[(short) ( 5 + offset)] = state[(short) ( 9 + offset)];
		state[(short) ( 9 + offset)] = state[(short) (13 + offset)];
		state[(short) (13 + offset)] = tmp;

		tmp = state[(short) (2 + offset)];
		state[(short) ( 2 + offset)] = state[(short) (10 + offset)];
		state[(short) (10 + offset)] = tmp;
		
		tmp = state[(short)(6 + offset)];
		state[(short) ( 6 + offset)] = state[(short) (14 + offset)];
		state[(short) (14 + offset)] = tmp;

		tmp = state[(short)(3 + offset)];
		state[(short) ( 3 + offset)] = state[(short) (15 + offset)];
		state[(short) (15 + offset)] = state[(short) (11 + offset)];
		state[(short) (11 + offset)] = state[(short) ( 7 + offset)];
		state[(short) ( 7 + offset)] = tmp;
		
        //Mix Columns
		zorro_MixColumns(state, offset);	
	}
	
    //one round of decryption
	void zorroOneRoundDec(byte[] state, short offset, byte round) {
		
		byte tmp;
        
        //Mix Columns
        zorro_InvMixColumns(state, offset);

        //Shift Rows
		tmp = state[(short) (13 + offset)];
		state[(short) (13 + offset)] = state[(short) ( 9 + offset)];
		state[(short) ( 9 + offset)] = state[(short) ( 5 + offset)];
		state[(short) ( 5 + offset)] = state[(short) ( 1 + offset)];
		state[(short) ( 1 + offset)] = tmp;

		tmp = state[(short) (2 + offset)];
		state[(short) ( 2 + offset)] = state[(short) (10 + offset)];
		state[(short) (10 + offset)] = tmp;
        
		tmp = state[(short) (6 + offset)];
		state[(short) ( 6 + offset)] = state[(short) (14 + offset)];
		state[(short) (14 + offset)] = tmp;

		tmp = state[(short)(3 + offset)];
		state[(short) ( 3 + offset)] = state[(short) ( 7 + offset)];
		state[(short) ( 7 + offset)] = state[(short) (11 + offset)];
		state[(short) (11 + offset)] = state[(short) (15 + offset)];
		state[(short) (15 + offset)] = tmp;

		//Add Constant
		state[(short) ( 0 + offset)] = (byte) (state[(short) ( 0 + offset)] ^  round);
		state[(short) ( 4 + offset)] = (byte) (state[(short) ( 4 + offset)] ^  round);
		state[(short) ( 8 + offset)] = (byte) (state[(short) ( 8 + offset)] ^  round);
		state[(short) (12 + offset)] = (byte) (state[(short) (12 + offset)] ^ (round << 3));

		//Sub Bytes
		state[(short)( 0 + offset)] = inv_s[(short) (state[(short) ( 0 + offset)] & 0x00ff)];
		state[(short)( 4 + offset)] = inv_s[(short) (state[(short) ( 4 + offset)] & 0x00ff)];
		state[(short)( 8 + offset)] = inv_s[(short) (state[(short) ( 8 + offset)] & 0x00ff)];
		state[(short)(12 + offset)] = inv_s[(short) (state[(short) (12 + offset)] & 0x00ff)];
	};

    //1 Step (4 rounds) of encryption
	void zorroFourRoundEnc(byte[] state, short state_offset, byte[] key, short key_offset, byte round) {
        
        short i;
        
		zorroOneRoundEnc(state, state_offset,         round     );
		zorroOneRoundEnc(state, state_offset, (byte) (round + 1));
		zorroOneRoundEnc(state, state_offset, (byte) (round + 2));
		zorroOneRoundEnc(state, state_offset, (byte) (round + 3));
		
		for (i = 0; i < 16; i++) state[(short) (i + state_offset)] ^= key[(short) (i + key_offset)];
	}
	
    //1 Step (4 rounds) of decryption
	void zorroFourRoundDec(byte[] state, short state_offset, byte[] key, short key_offset, byte round) {
		
        short i;
        
		zorroOneRoundDec(state, state_offset,         round     );
		zorroOneRoundDec(state, state_offset, (byte) (round - 1));
		zorroOneRoundDec(state, state_offset, (byte) (round - 2));
		zorroOneRoundDec(state, state_offset, (byte) (round - 3));
        
		for (i = 0; i < 16; i++) state[(short) (i + state_offset)] ^= key[(short) (i + key_offset)];
	}

    //Complete encryption routine
	void zorroCompleteEnc(byte[] state, short state_offset, byte[] key, short key_offset) {
        
        short i;
        
	    for (i = 0; i < 16; i++) state[(short) (i + state_offset)] ^= key[(short) (i + key_offset)];
        
	    zorroFourRoundEnc(state, state_offset, key, key_offset, (byte)  1);
	    zorroFourRoundEnc(state, state_offset, key, key_offset, (byte)  5);
	    zorroFourRoundEnc(state, state_offset, key, key_offset, (byte)  9);
	    zorroFourRoundEnc(state, state_offset, key, key_offset, (byte) 13);
	    zorroFourRoundEnc(state, state_offset, key, key_offset, (byte) 17);
	    zorroFourRoundEnc(state, state_offset, key, key_offset, (byte) 21);
	 
	}
	
    //Complete decryption routine
	void zorroCompleteDec(byte[] state, short state_offset, byte[] key, short key_offset) {
        
	    short i;
        
	    for (i = 0; i < 16; i++)	state[(short) (i + state_offset)] ^= key[(short) (i + key_offset)];
        
	    zorroFourRoundDec(state, state_offset, key, key_offset, (byte) 24);
	    zorroFourRoundDec(state, state_offset, key, key_offset, (byte) 20);
	    zorroFourRoundDec(state, state_offset, key, key_offset, (byte) 16);
	    zorroFourRoundDec(state, state_offset, key, key_offset, (byte) 12);
	    zorroFourRoundDec(state, state_offset, key, key_offset, (byte)  8);
	    zorroFourRoundDec(state, state_offset, key, key_offset, (byte)  4);
	}
	
	public static ZorroCipher getInstance()	{
		if(m_instance == null)
			m_instance = new ZorroCipher();
		return m_instance;
	}

	//Public method for encryption/decryption - supports only 1 block (16 bytes)
	public short doFinal(byte[]  inBuff, short inOffset, short inLength,
						 byte[] outBuff, short outOffset) throws CryptoException {

		//not initialized
		if(!isInitialized)
			throw new CryptoException(CryptoException.INVALID_INIT);
        
        //not initialized
		if(!cipherKey.isInitialized())
			throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
        
        //supports just one block
		if(inLength != 16)
			throw new CryptoException(CryptoException.ILLEGAL_USE);
        
		if(mode == Cipher.MODE_ENCRYPT)
		{
			Util.arrayCopy(inBuff, inOffset, temp, (short) 0, inLength);
			cipherKey.getKey(temp, inLength);
			zorroCompleteEnc(temp, (short) 0, temp, (short) 16);
			Util.arrayCopy(temp, (short) 0, outBuff, outOffset, (short) 16);
			Util.arrayFillNonAtomic(temp, (byte) 0, MAX_MEMORY_TEMPORARY, (byte) 0x00); //reset all values

			return (short) 16;
		}
		else //decrypt
		{
			Util.arrayCopy(inBuff, inOffset, temp, (short) 0, inLength);
			cipherKey.getKey(temp, inLength);
			zorroCompleteDec(temp,(short) 0, temp, (short) 16);
			Util.arrayCopy(temp, (short) 0, outBuff, outOffset, (short) 16);
			Util.arrayFillNonAtomic(temp, (byte) 0, MAX_MEMORY_TEMPORARY, (byte) 0x00); //reset all values

			return (short) 16;
		}
	}
    
    //Get Algorithm
	public byte getAlgorithm() {
		return ALG_ZORRO;
	}
    
	//init with a 128bit DESkey
	public void init(Key key, byte mode) throws CryptoException	{
		
        if(!key.isInitialized())
			throw new CryptoException(CryptoException.UNINITIALIZED_KEY);
        
		if(key.getSize() != 128 || key.getType() != KeyBuilder.TYPE_DES)
			throw new CryptoException(CryptoException.ILLEGAL_VALUE);
        
		this.mode = mode;
		cipherKey = (DESKey) key;
		isInitialized = true;
	}

	//not using this mode of init, throw exception
	public void init(Key key, byte mode, byte[] buf, short bOff, short bLen) throws CryptoException	{
		throw new CryptoException(CryptoException.INVALID_INIT);
	}

    //not using this mode of init, throw exception
	public short update(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws CryptoException {
		throw new CryptoException(CryptoException.ILLEGAL_USE);
	}
}
