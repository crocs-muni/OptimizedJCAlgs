/**
 * Java Card implementation of the OpenPGP card
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
 */
package openpgp;

import javacard.framework.*;
import javacard.security.*;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 * @review Matej Evin
 */
public class PGPKey implements ISO7816 {
    
    // Constants
    public static final short KEY_SIZE              = 2048;         
    public static final short KEY_SIZE_BYTES        = KEY_SIZE / 8; // 256
    public static final short EXPONENT_SIZE         = 17;
    public static final short EXPONENT_SIZE_BYTES   = 3;
    public static final short FP_SIZE               = 20;           // Fingerprint size
    public static final short TIME_SIZE             = 4;            // Time size
    public static final short ATTR_SIZE             = 6;            // Attributes array size
    
    // Macros
    public static final short _0                    = (short) 0;
    
    // Key structure
    final KeyPair   key;
    final byte[]    fp;
    final byte[]    time = { 0x00, 0x00, 0x00, 0x00 };
    final byte[]    attributes = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x02 };

    // Constructor
    public PGPKey() {
        key = new KeyPair(KeyPair.ALG_RSA_CRT, KEY_SIZE);

        fp = new byte[FP_SIZE];
        Util.arrayFillNonAtomic(fp, _0, FP_SIZE, (byte) 0);

        Util.setShort(attributes, (short) 1, KEY_SIZE);
        Util.setShort(attributes, (short) 3, EXPONENT_SIZE);
    }

    //Set the fingerprint for the public key.
    public void setFingerprint(byte[] data, short offset) {
        // Check whether there are enough bytes to copy
        if ((short) (offset + FP_SIZE) > data.length)
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);

        Util.arrayCopy(data, offset, fp, _0, FP_SIZE);
    }

    // Set the generation time for the key pair.
    public void setTime(byte[] data, short offset) {
        // Check whether there are enough bytes to copy
        if ((short) (offset + TIME_SIZE) > data.length)
            throw new CryptoException(CryptoException.ILLEGAL_VALUE);

        Util.arrayCopy(data, offset, time, _0, TIME_SIZE);
    }

    //Get the fingerprint for the public key.
    public short getFingerprint(byte[] data, short offset) {
        Util.arrayCopyNonAtomic(fp, _0, data, offset, FP_SIZE);
        return (short) (offset + FP_SIZE);
    }

    //Get the generation time for the key pair.
    public short getTime(byte[] data, short offset) {
        Util.arrayCopyNonAtomic(time, _0, data, offset, TIME_SIZE);
        return (short) (offset + TIME_SIZE);
    }

    //Get the algorithm attributes for the key pair.
    public short getAttributes(byte[] data, short offset) {
        Util.arrayCopyNonAtomic(attributes, _0, data, offset, ATTR_SIZE);
        return (short) (offset + ATTR_SIZE);
    }
}
