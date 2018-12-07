/**
 * Java Card implementation of the OpenPGP card
 * 
 * Copyright (C) 2011  Joeri de Ruiter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * OpenPGPSecureMessaging.java is based on OVSecureMessaging.java which is part
 * of OVchip-ng
 * 
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, February 2011.
 */

package openpgp;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * OpenPGP secure messaging functionality.
 * 
 * @author Pim Vullers
 * @review Matej Evin
 */
public class OpenPGPSecureMessaging {
    
    // Codes
    private static final short SW_INTERNAL_ERROR = (short) 0x6D66;
    
    // Macros
    private static final short _0 = (short) 0;
    
    
    // EEPROM Arrays
    private static final byte[] PAD_DATA = {(byte) 0x80, 0, 0, 0, 0, 0, 0, 0};
    private static final byte[] EMPTY_KEY = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    
    // Defines
    static final short TMP_SIZE = 256;
    static final short MAC_SIZE = 8;
    static final short KEY_SIZE = 16;
    static final short SSC_SIZE = 8;

    // Cryptographic functionality
    private final Signature signer;
    private final Signature verifier;
    private final Cipher    cipher;
    private final Cipher    decipher;

    // Keys
    private final DESKey    keyMAC;
    private final DESKey    keyENC;
    
    // RAM Arrays
    boolean ssc_set[]           = null; // SSC flag
    byte[]  ssc                 = null; // Send sequence counter
    private byte[] tmp          = null; // Temporary data
    
    
    // Constructor
    public OpenPGPSecureMessaging() {
        ssc         = JCSystem.makeTransientByteArray(SSC_SIZE, JCSystem.CLEAR_ON_DESELECT);
        tmp         = JCSystem.makeTransientByteArray(TMP_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        signer      = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
        verifier    = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
        
        cipher      = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
        decipher    = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
        
        keyMAC = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_2KEY, false);
        keyENC = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_2KEY, false);
        
        ssc_set = JCSystem.makeTransientBooleanArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        ssc_set[0] = false;
    }

    /**
     * Set the MAC and encryption (and decryption) session keys. Each key is a 
     * 16 byte 3DES EDE key. This method may be called at any time and will 
     * immediately replace the session key.
     * 
     * @param buffer byte array containing the session keys.
     * @param offset location of the session keys in the buffer.
     */
    public void setSessionKeys(byte[] buffer, short offset) {
        // Check for empty keys
        if(Util.arrayCompare(buffer, _0,       EMPTY_KEY, _0, KEY_SIZE) == 0 ||
           Util.arrayCompare(buffer, KEY_SIZE, EMPTY_KEY, _0, KEY_SIZE) == 0) {
            keyMAC.clearKey();
            keyENC.clearKey();
        }
        else {        
            keyMAC.setKey(buffer, offset);
            keyENC.setKey(buffer, (short) (offset + KEY_SIZE));
        
            signer.init(keyMAC, Signature.MODE_SIGN);
            verifier.init(keyMAC, Signature.MODE_VERIFY);
        
            cipher.init(keyENC, Cipher.MODE_ENCRYPT);
            decipher.init(keyENC, Cipher.MODE_DECRYPT);
        }
    }
    
    /**
     * Set the MAC session key. Each key is a 16 byte 3DES EDE key. This method 
     * may be called at any time and will immediately replace the session key.
     * 
     * @param buffer byte array containing the session key.
     * @param offset location of the session key in the buffer.
     */
    public void setSessionKeyMAC(byte[] buffer, short offset) {
        // Check for empty keys
        if(Util.arrayCompare(buffer, _0, EMPTY_KEY, _0, KEY_SIZE) == 0) {
            keyMAC.clearKey();
            keyENC.clearKey();
        }
        else {         
            keyMAC.setKey(buffer, offset);
        
            signer.init(keyMAC, Signature.MODE_SIGN);
            verifier.init(keyMAC, Signature.MODE_VERIFY);
        }
    }

    /**
     * Set the encryption session key. Each key is a 16 byte 3DES EDE key. This method 
     * may be called at any time and will immediately replace the session key.
     * 
     * @param buffer byte array containing the session key.
     * @param offset location of the session key in the buffer.
     */
    public void setSessionKeyEncryption(byte[] buffer, short offset) {
        // Check for empty keys
        if(Util.arrayCompare(buffer, _0, EMPTY_KEY, _0, KEY_SIZE) == 0) {
            keyMAC.clearKey();
            keyENC.clearKey();
        }
        else {         
            keyENC.setKey(buffer, (short) (offset + KEY_SIZE));
        
            cipher.init(keyENC, Cipher.MODE_ENCRYPT);
            decipher.init(keyENC, Cipher.MODE_DECRYPT);
        }
    }
    
    /**
     * Unwraps (verify and decrypt) the command APDU located in the APDU buffer.
     * The command buffer has to be filled by the APDU.setIncomingAndReceive()
     * method beforehand. The verified and decrypted command data get placed at
     * the start of the APDU buffer.
     * 
     * @return the length value encoded by DO97, 0 if this object is missing.
     */
    public short unwrapCommandAPDU() {
        byte[] buf = APDU.getCurrentAPDUBuffer();
        short apdu_p = (short) (ISO7816.OFFSET_CDATA & 0xff);
        short start_p = apdu_p;
        short le = 0;
        short do87DataLen = 0;
        short do87Data_p = 0;
        short do87LenBytes;
        short hdrLen = 4;
        short hdrPadLen = (short) (8 - hdrLen);

        // Increment SSC
        for (short s = 7; s >= 0; s--) {
            if ((ssc[s] & 0xff) == 0xff) {
                ssc[s] = 0;
            } else {
                ssc[s]++;
                break;
            }
        }

        if (buf[apdu_p] == (byte) 0x87) {
            apdu_p++;
            // do87
            if ((buf[apdu_p] & 0xff) > 0x80) {
                do87LenBytes = (short) (buf[apdu_p] & 0x7f);
                apdu_p++;
            } else {
                do87LenBytes = 1;
            }
            if (do87LenBytes > 2) { // sanity check
                ISOException.throwIt(SW_INTERNAL_ERROR);
            }
            for (short i = 0; i < do87LenBytes; i++) {
                do87DataLen += (short) ((buf[(short)(apdu_p + i)] & 0xff) << (short) ((do87LenBytes - 1 - i) * 8));
            }
            apdu_p += do87LenBytes;

            if (buf[apdu_p] != 1) {
                ISOException.throwIt(SW_INTERNAL_ERROR);
            }
            // store pointer to data and defer decrypt to after mac check (do8e)
            do87Data_p = (short) (apdu_p + 1);
            apdu_p += do87DataLen;
            do87DataLen--; // compensate for 0x01 marker
        }

        if (buf[apdu_p] == (byte) 0x97) {
            // do97
            if (buf[++apdu_p] != 1)
                ISOException.throwIt(SW_INTERNAL_ERROR);
            le = (short) (buf[++apdu_p] & 0xff);
            apdu_p++;
        }

        // do8e
        if (buf[apdu_p] != (byte) 0x8e) {
            ISOException.throwIt(SW_INTERNAL_ERROR);
        }
        if (buf[++apdu_p] != 8) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // verify mac
        verifier.update(ssc, (short)0, SSC_SIZE);
        verifier.update(buf, (short)0, hdrLen);
        verifier.update(PAD_DATA, (short)0, hdrPadLen);
        if (!verifier.verify(buf, start_p, (short) (apdu_p - 1 - start_p), buf, 
                (short)(apdu_p + 1), MAC_SIZE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if (do87DataLen != 0) {
            // decrypt data, and leave room for lc
            short lc = decipher.doFinal(buf, do87Data_p, do87DataLen, buf, 
                    (short) (hdrLen + 1));
            buf[hdrLen] = (byte) (lc & 0xff);
        }

        return le;
    }

    /**
     * Wraps (encrypts and build MAC) the response data and places it in the
     * APDU buffer starting at offset 0. The buffer can be any buffer including
     * the APDU buffer itself. If the length is zero the buffer will not be
     * addressed and no response data will be present in the wrapped output.
     * 
     * @param buffer byte array containing the data which needs to be wrapped.
     * @param offset location of the data in the buffer.
     * @param length of the data in the buffer (in bytes).
     * @param status word which has to be wrapped in the response APDU.
     * @return the length of the wrapped data in the apdu buffer
     */
    public short wrapResponseAPDU(byte[] buffer, short offset, short length, short status) {
        byte[] apdu = APDU.getCurrentAPDUBuffer();
        short apdu_p = 0;
        // smallest multiple of 8 strictly larger than plaintextLen (length + padding) + 1 byte for 0x01 marker (indicating padding is used)
        short do87DataLen = (short) ((((short) (length + 8) / 8) * 8) + 1);
        short do87DataLenBytes = (short)(do87DataLen > 0xff ? 2 : 1);
        short do87HeaderBytes = (length < 120 || (length > 247 && length < 256)) ? (short) 3 : (short) 4; // length between 0-119 and 248-255 return 3, else 4
        short do87Bytes = (short)(do87HeaderBytes + do87DataLen - 1); // 0x01 was counted twice 
        boolean hasDo87 = length > 0;

        // Increment SSC
        for (short s = 7; s >= 0; s--) {
            if ((ssc[s] & 0xff) == 0xff) {
                ssc[s] = 0;
            } else {
                ssc[s]++;
                break;
            }
        }

        short ciphertextLength = 0;
        if(hasDo87) {
            // Copy the plain text to temporary buffer to avoid data corruption.
            Util.arrayCopyNonAtomic(buffer, offset, tmp, (short) 0, length);
            // Put the cipher text in the proper position.
            ciphertextLength = cipher.doFinal(tmp, (short) 0, length, apdu, 
                    do87HeaderBytes);
        }
        //sanity check
        //note that this check
        //  (possiblyPaddedPlaintextLength != (short)(do87DataLen -1))
        //does not always hold because some algs do the padding in the final, some in the init.
        if (hasDo87 && (((short) (do87DataLen - 1) != ciphertextLength)))
            ISOException.throwIt(SW_INTERNAL_ERROR);
        
        if (hasDo87) {
            // build do87
            apdu[apdu_p++] = (byte) 0x87;
            if(do87DataLen < 0x80) {
                apdu[apdu_p++] = (byte)do87DataLen; 
            } else {
                apdu[apdu_p++] = (byte) (0x80 + do87DataLenBytes);
                for(short i = (short) (do87DataLenBytes - 1); i >= 0; i--) {
                    apdu[apdu_p++] = (byte) ((do87DataLen >>> (i * 8)) & 0xff);
                }
            }
            apdu[apdu_p++] = 0x01;
        }

        if(hasDo87) {
            apdu_p = do87Bytes;
        }
        
        // build do99
        apdu[apdu_p++] = (byte) 0x99;
        apdu[apdu_p++] = 0x02;
        Util.setShort(apdu, apdu_p, status);
        apdu_p += 2;

        // calculate and write mac
        signer.update(ssc, (short) 0, SSC_SIZE);
        signer.sign(apdu, (short) 0, apdu_p, apdu, (short) (apdu_p + 2));

        // write do8e
        apdu[apdu_p++] = (byte) 0x8e;
        apdu[apdu_p++] = 0x08;
        apdu_p += 8; // for mac written earlier

        return apdu_p;
    }
}
