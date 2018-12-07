package openpgp;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class OpenPGPApplet extends Applet implements ISO7816 {
    
    private static final short _0 = 0;
    
    private static final boolean FORCE_SM_GET_CHALLENGE = true;

    private static final byte[] HISTORICAL = {
        0x0, 0x73, 0x0, 0x0, (byte) 0x80, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

    private static final byte[] EXTENDED_CAP = { 
            (byte) 0xF0,        // Support for GET CHALLENGE
                                // Support for Key Import
                                // PW1 Status byte changeable
            0x0,                // Secure messaging using 3DES
            0x0, (byte) 0xFF,   // Maximum length of challenges
            0x0, (byte) 0xFF,   // Maximum length Cardholder Certificate
            0x0, (byte) 0xFF,   // Maximum length command data
            0x0, (byte) 0xFF    // Maximum length response data
    };

    // Length constraints
    private static final short  RESPONSE_MAX_LENGTH     = 255;
    private static final short  RESPONSE_SM_MAX_LENGTH  = 231;
    private static final short  CHALLENGES_MAX_LENGTH   = 255;
    private static final short  BUFFER_MAX_LENGTH       = 674;
    private static final short  LOGINDATA_MAX_LENGTH    = 254;
    private static final short  URL_MAX_LENGTH          = 254;
    private static final short  NAME_MAX_LENGTH         = 39;
    private static final short  LANG_MAX_LENGTH         = 8;
    private static final short  CERT_MAX_LENGTH         = 500;

    // PIN
    private static final byte[] PW1_DEFAULT = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36 }; // Default '123456'
    private static final byte   PW1_MIN_LENGTH          = 6;
    private static final byte   PW1_MAX_LENGTH          = 127;
    private static final byte   PW1_MODE_NO81           = 0;
    private static final byte   PW1_MODE_NO82           = 1;

    // Resetting code
    private static final byte   RC_MIN_LENGTH           = 8;
    private static final byte   RC_MAX_LENGTH           = 127;

    // Administrator PIN
    private static final byte   PW3_MIN_LENGTH          = 8;
    private static final byte   PW3_MAX_LENGTH          = 127;
    private static final byte[] PW3_DEFAULT = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 }; // Default '12345678'

    // Login Data
    private final byte[] loginData = new byte[LOGINDATA_MAX_LENGTH];
    private short loginData_length = 0;

    // URL
    private final byte[] url = new byte[URL_MAX_LENGTH];
    private short url_length = 0;

    // Name
    private final byte[] name = new byte[NAME_MAX_LENGTH];
    private short name_length = 0;

    // Language
    private final byte[] lang = new byte[LANG_MAX_LENGTH];
    private short lang_length = 0;

    // Certificate
    private final byte[] cert = new byte[CERT_MAX_LENGTH];
    private short cert_length = 0;

    //Sex
    private byte sex = 0x39;

    // PIN
    private final OwnerPIN pw1;
    private byte pw1_length = 0;
    private byte pw1_status = 0x0;
    private final boolean[] pw1_modes;

    // Resetting code
    private final OwnerPIN rc;
    private byte rc_length = 0;

    // Administrator PIN
    private final OwnerPIN pw3;
    private byte pw3_length = 0;

    // Digital signature counter
    private final byte[] ds_counter = { 0x0, 0x0, 0x0 };
    private final static short DS_CTR_LENGTH = 3;

    // PGP Keys
    private final PGPKey sig_key;
    private final PGPKey dec_key;
    private final PGPKey auth_key;

    // Certification Authority fingerprints
    private final byte[] ca1_fp = {
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    private final byte[] ca2_fp = {
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    private final byte[] ca3_fp = {
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    // Cryptographic engines
    private final Cipher cipher;
    private final RandomData random;

    // Temporary data buffer
    private final byte[] tmp;
    private final byte[] buffer;
    
    // Counters
    private short out_left = 0;
    private short out_sent = 0;
    private short in_received = 0;

    // Message Chaining
    private boolean chain = false;
    private byte chain_ins = 0;
    private short chain_p1p2 = 0;
    
    // Secure Messaging
    private final OpenPGPSecureMessaging sm;
    private boolean sm_success = false;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new OpenPGPApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public OpenPGPApplet() {
        // Create temporary arrays
        tmp         = JCSystem.makeTransientByteArray(BUFFER_MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        buffer      = JCSystem.makeTransientByteArray(BUFFER_MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        pw1_modes   = JCSystem.makeTransientBooleanArray((short) 2,      JCSystem.CLEAR_ON_DESELECT);

        // Initialize PW1 with default password
        pw1 = new OwnerPIN((byte) 3, PW1_MAX_LENGTH);
        pw1.update(PW1_DEFAULT, _0, (byte) PW1_DEFAULT.length);
        pw1_length = (byte) PW1_DEFAULT.length;

        // Initialize RC
        rc = new OwnerPIN((byte) 3, RC_MAX_LENGTH);

        // Initialize PW3 with default password
        pw3 = new OwnerPIN((byte) 3, PW3_MAX_LENGTH);
        pw3.update(PW3_DEFAULT, _0, (byte) PW3_DEFAULT.length);
        pw3_length = (byte) PW3_DEFAULT.length;

        // Create empty keys
        sig_key  = new PGPKey();
        dec_key  = new PGPKey();
        auth_key = new PGPKey();

        // Prepare engines
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        
        // Initialize Secure Messaging
        sm = new OpenPGPSecureMessaging();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            // Reset PW1 modes
            pw1_modes[PW1_MODE_NO81] = false;
            pw1_modes[PW1_MODE_NO82] = false;

            return;
        }

        byte[] buf = apdu.getBuffer();
        byte cla = buf[OFFSET_CLA];
        byte ins = buf[OFFSET_INS];
        byte p1 = buf[OFFSET_P1];
        byte p2 = buf[OFFSET_P2];
        short p1p2 = Util.makeShort(p1, p2);
        short lc = (short) (buf[OFFSET_LC] & 0xFF);
 
        // Secure messaging
        sm_success = false;
        if ((byte) (cla & (byte) 0x0C) == (byte) 0x0C) {
            // Force initialization of SSC before using SM to prevent replays
            if(FORCE_SM_GET_CHALLENGE && !sm.ssc_set[0] && (ins != (byte) 0x84)) ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
                
            lc = sm.unwrapCommandAPDU();
            sm_success = true;
        }
        
        short status = SW_NO_ERROR;
        short le = 0;
        
        try {
            // Support for command chaining
            commandChaining(apdu);
    
            // Reset buffer for GET RESPONSE
            if (ins != (byte) 0xC0) {
                out_sent = 0;
                out_left = 0;
            }
    
            // Other instructions
            switch (ins) {
                // GET RESPONSE
                case (byte) 0xC0:
                    // Will be handled in finally clause
                    break;
            
                // VERIFY
                case (byte) 0x20:
                    verify(p2);
                    break;
    
                // CHANGE REFERENCE DATA
                case (byte) 0x24:
                    changeReferenceData(p2);
                    break;
    
                // RESET RETRY COUNTER
                case (byte) 0x2C:
                    // Reset only available for PW1
                    if (p2 != (byte) 0x81)
                        ISOException.throwIt(SW_INCORRECT_P1P2);
    
                    resetRetryCounter(p1);
                    break;
    
                // PERFORM SECURITY OPERATION
                case (byte) 0x2A:
                    // COMPUTE DIGITAL SIGNATURE
                    switch (p1p2) {
                        case (short) 0x9E9A:
                            le = computeDigitalSignature();
                            break;
                        case (short) 0x8086:
                            le = decipher();
                            break;
                        default:
                            ISOException.throwIt(SW_WRONG_P1P2);
                            break;
                    }
                    break;
    
                // INTERNAL AUTHENTICATE
                case (byte) 0x88:
                    le = internalAuthenticate();
                    break;
    
                // GENERATE ASYMMETRIC KEY PAIR
                case (byte) 0x47:
                    le = genAsymKey(p1);
                    break;
    
                // GET CHALLENGE
                case (byte) 0x84:
                    le = getChallenge(lc);
                    break;
    
                // GET DATA
                case (byte) 0xCA:
                    le = getData(p1p2);
                    break;
    
                // PUT DATA
                case (byte) 0xDA:
                    putData(p1p2);
                    break;
    
                // DB - PUT DATA (Odd)
                case (byte) 0xDB:
                    // Odd PUT DATA only supported for importing keys
                    // 4D - Extended Header list
                    if (p1p2 == (short) 0x3FFF) {
                        importKey();
                    } else {
                        ISOException.throwIt(SW_RECORD_NOT_FOUND);
                    }
                    break;
    
                default:
                    // good practice: If you don't know the INStruction, say so:
                    ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
        }
        catch(ISOException e) {
            status = e.getReason();
        }
        finally {
            if(status != (short) 0x9000) {
                // Send the exception that was thrown 
                out_sent = 0;
                out_left = 0;
                sendNext(apdu, status);   
            } else {
                // GET RESPONSE
                if (ins == (byte) 0xC0) {
                    sendNext(apdu, SW_NO_ERROR);
                } else {
                    // Send Buffer
                    out_sent = 0;
                    out_left = le;
                    sendNext(apdu, SW_NO_ERROR);
                }
            }
        }
    }

    /**
     * Provide support for command chaining - store the received data in buffer
     * 
     * @param apdu
     */
    private void commandChaining(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short p1p2 = Util.makeShort(buf[OFFSET_P1],    buf[OFFSET_P2]);
        short len = (short) (buf[OFFSET_LC] & 0xFF);

        // Reset chaining if it was not yet initiated
        if (!chain) {
            chain = false;
            in_received = 0;
        }

        if ((byte) (buf[OFFSET_CLA] & (byte) 0x10) == (byte) 0x10) {
            // If chaining was already initiated, INS and P1P2 should match
            if (chain && (buf[OFFSET_INS] != chain_ins && p1p2 != chain_p1p2)) {
                chain = false;
                in_received = 0;
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }

            // Check whether data to be received is larger than size of the buffer
            if ((short) (in_received + len) > BUFFER_MAX_LENGTH) {
                chain = false;
                in_received = 0;
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            // Store received data in buffer
            in_received = Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, buffer, in_received, len);

            chain = true;
            chain_ins = buf[OFFSET_INS];
            chain_p1p2 = p1p2;

            ISOException.throwIt(SW_NO_ERROR);
        }

        if (chain && buf[OFFSET_INS] == chain_ins && p1p2 == chain_p1p2) {
            chain = false;

            // Check whether data to be received is larger than size of the
            // buffer
            if ((short) (in_received + len) > BUFFER_MAX_LENGTH) {
                chain = false;
                in_received = 0;
                ISOException.throwIt(SW_WRONG_LENGTH);
            }

            // Add received data to the buffer
            in_received = Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, buffer, in_received, len);
        } else if (chain) {
            // Chained command expected
            chain = false;
            in_received = 0;
            ISOException.throwIt(SW_UNKNOWN);
        } else {
            // No chaining was used, so copy data to buffer
            in_received = Util.arrayCopyNonAtomic(buf, OFFSET_CDATA, buffer, _0, len);
        }
    }

    /**
     * (INS 20)
     * Verify one of the passwords depending on mode:
     * - 81: PW1 for a PSO:CDS command
     * - 82: PW1 for other commands
     * - 83: PW3
     * 
     * @param mode Password and mode to be verified
     */
    private void verify(byte mode) {
        if (mode == (byte) 0x81 || mode == (byte) 0x82) {
            // Check length of input
            if (in_received < PW1_MIN_LENGTH || in_received > PW1_MAX_LENGTH)
                ISOException.throwIt(SW_WRONG_LENGTH);

            // Check given PW1 and set requested mode if verified succesfully
            if (pw1.check(buffer, _0, (byte) in_received)) {
                if (mode == (byte) 0x81)
                    pw1_modes[PW1_MODE_NO81] = true;
                else
                    pw1_modes[PW1_MODE_NO82] = true;
            } else {
                ISOException.throwIt((short) (0x63C0 | pw1.getTriesRemaining()));
            }
        } else if (mode == (byte) 0x83) {
            // Check length of input
            if (in_received < PW3_MIN_LENGTH || in_received > PW3_MAX_LENGTH)
                ISOException.throwIt(SW_WRONG_LENGTH);

            // Check PW3
            if (!pw3.check(buffer, _0, (byte) in_received)) {
                ISOException.throwIt((short) (0x63C0 | pw3.getTriesRemaining()));
            }
        } else {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
    }

    /**
     * (INS 24)
     * Change the password specified using mode: - 81: PW1 - 82: PW3
     * 
     * @param mode which password (PIN) should be changed
     */
    private void changeReferenceData(byte mode) {
        if (mode == (byte) 0x81) {
            // Check length of the new password
            short new_length = (short) (in_received - pw1_length);
            if (new_length < PW1_MIN_LENGTH || new_length > PW1_MAX_LENGTH)
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            if (!pw1.check(buffer, _0, pw1_length))
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            // Change PW1
            JCSystem.beginTransaction();
            pw1.update(buffer, pw1_length, (byte) new_length);
            pw1_length = (byte) new_length;
            pw1_modes[PW1_MODE_NO81] = false;
            pw1_modes[PW1_MODE_NO82] = false;
            JCSystem.commitTransaction();
        } else if (mode == (byte) 0x83) {
            // Check length of the new password
            short new_length = (short) (in_received - pw3_length);
            if (new_length < PW3_MIN_LENGTH || new_length > PW3_MAX_LENGTH)
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            if (!pw3.check(buffer, _0, pw3_length))
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            // Change PW3
            JCSystem.beginTransaction();
            pw3.update(buffer, pw3_length, (byte) new_length);
            pw3_length = (byte) new_length;
            JCSystem.commitTransaction();
        } else {
            ISOException.throwIt(SW_INCORRECT_P1P2);
        }
    }

    /**
     * (INS 2C)
     * Reset PW1 either using the Resetting Code (mode = 00) or PW3 (mode = 02)
     * 
     * @param mode Mode used to reset PW1
     */
    private void resetRetryCounter(byte mode) {
        if (mode == (byte) 0x0) {
            // Authentication using RC
            if (rc_length == 0)
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            short new_length = (short) (in_received - rc_length);
            if (new_length < PW1_MIN_LENGTH || new_length > PW1_MAX_LENGTH)
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            if (!rc.check(buffer, _0, rc_length))
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            // Change PW1
            JCSystem.beginTransaction();
            pw1.update(buffer, rc_length, (byte) new_length);
            pw1_length = (byte) new_length;
            JCSystem.commitTransaction();
        } else if (mode == (byte) 0x02) {
            // Authentication using PW3
            if (!pw3.isValidated())
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

            if (in_received < PW1_MIN_LENGTH || in_received > PW1_MAX_LENGTH)
                ISOException.throwIt(SW_WRONG_LENGTH);

            // Change PW1
            JCSystem.beginTransaction();
            pw1.update(buffer, _0, (byte) in_received);
            pw1_length = (byte) in_received;
            JCSystem.commitTransaction();
        } else {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
    }

    /**
     * (INS 2A, P1P2 9E9A)
     * Sign the data provided using the key for digital signatures.
     * 
     * Before using this method PW1 has to be verified with mode No. 81.
     * If the first status byte of PW1 is 00,
     * access condition PW1 with No. 81 is reset.
     * 
     * @return Length of data written in buffer
     */
    private short computeDigitalSignature() {
        if (!(pw1.isValidated() && pw1_modes[PW1_MODE_NO81]))
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        if (pw1_status == (byte) 0x0)
            pw1_modes[PW1_MODE_NO81] = false;

        if (!((RSAPrivateCrtKey) sig_key.key.getPrivate()).isInitialized())
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

        // Copy data to be signed to tmp
        short length = Util.arrayCopyNonAtomic(buffer, _0, tmp, _0, in_received);

        cipher.init(sig_key.key.getPrivate(), Cipher.MODE_ENCRYPT);
        
        // Increase DS counter
        for (short i = 2; i >= 0; i--) {
            if ((ds_counter[i] & 0xff) == 0xff) {
                ds_counter[i] = 0; // It would take 16,777,215 signings to overflow
            } else {
                ds_counter[i]++;
                break;
            }
        }

        return cipher.doFinal(tmp, _0, length, buffer, _0);
    }

    /**
     * (INS 2A, P1P2 8086)
     * Decrypt the data provided using the key for confidentiality.
     * 
     * Before using this method PW1 has to be verified with mode No. 82.
     * 
     * @return Length of data written in buffer
     */
    private short decipher() {
        if (!(pw1.isValidated() && pw1_modes[PW1_MODE_NO82]))
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        if (!(dec_key.key.getPrivate().isInitialized()))
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

        // Copy data to be decrypted to tmp, omit padding indicator
        short length = Util.arrayCopyNonAtomic(buffer, (short) 1, tmp, _0,
                (short) (in_received - 1));

        cipher.init(dec_key.key.getPrivate(), Cipher.MODE_DECRYPT);

        return cipher.doFinal(tmp, _0, length, buffer, _0);
    }

    /**
     * (INS 88)
     * Sign the data provided using the key for authentication.
     * Before using this method PW1 has to be verified with mode No. 82.
     * 
     * @return Length of data written in buffer
     */
    private short internalAuthenticate() {
        if (!(pw1.isValidated() && pw1_modes[PW1_MODE_NO82]))
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        Util.arrayCopyNonAtomic(buffer, _0, tmp, _0, in_received);

        if (!(auth_key.key.getPrivate().isInitialized()))
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);

        cipher.init(auth_key.key.getPrivate(), Cipher.MODE_ENCRYPT);
        return cipher.doFinal(tmp, _0, in_received, buffer, _0);
    }

    /**
     * (INS 47)
     * For mode 80, generate a new key pair, specified in the first element of
     * buffer, and output the public key.
     * For mode 81, output the public key specified in the first element of
     * buffer.
     * 
     * Before using this method PW3 has to be verified.
     * 
     * @param mode Generate key pair (80) or read public key (81)
     * @return Length of data written in buffer
     */
    private short genAsymKey(byte mode) {
        PGPKey a_key = sig_key;
        switch (buffer[0]) {
            case (byte) 0xB6: /*a_key = sig_key*/ break;
            case (byte) 0xB8: a_key = dec_key;    break;
            case (byte) 0xA4: a_key = auth_key;   break;
            default: ISOException.throwIt(SW_UNKNOWN);
        }

        if (mode == (byte) 0x80) {
            if (!pw3.isValidated())
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

            JCSystem.beginTransaction();
            a_key.key.genKeyPair();
            
            if (buffer[0] == (byte) 0xB6) {
                // Reset signature counter
                for(short i = 0; i < DS_CTR_LENGTH; i++) {
                    ds_counter[i] = (byte) 0;
                }
            }
            JCSystem.commitTransaction();
        }

        // Output requested key
        RSAPublicKey pubkey = (RSAPublicKey) a_key.key.getPublic();

        // Build message in tmp
        short offset = 0;

        // 81 - Modulus
        tmp[offset++] = (byte) 0x81;

        // Length of modulus is always greater than 128 bytes
        if (PGPKey.KEY_SIZE_BYTES < 256) {
            tmp[offset++] = (byte) 0x81;
            tmp[offset++] = (byte) PGPKey.KEY_SIZE_BYTES;
        } else {
            tmp[offset++] = (byte) 0x82;
            offset = Util.setShort(tmp, offset, PGPKey.KEY_SIZE_BYTES);
        }
        pubkey.getModulus(tmp, offset);
        offset += PGPKey.KEY_SIZE_BYTES;

        // 82 - Exponent
        tmp[offset++] = (byte) 0x82;
        tmp[offset++] = (byte) PGPKey.EXPONENT_SIZE_BYTES;
        pubkey.getExponent(tmp, offset);
        offset += PGPKey.EXPONENT_SIZE_BYTES;

        short len = offset;

        offset = 0;

        buffer[offset++] = 0x7F;
        buffer[offset++] = 0x49;

        if (len < 256) {
            buffer[offset++] = (byte) 0x81;
            buffer[offset++] = (byte) len;
        } else {
            buffer[offset++] = (byte) 0x82;
            offset = Util.setShort(buffer, offset, len);
        }

        offset = Util.arrayCopyNonAtomic(tmp, _0, buffer, offset, len);

        return offset;
    }

    /**
     * (INS 84)
     * Generate a random number of the length given in len.
     * 
     * @param len Length of the requested challenge
     * @return Length of data written in buffer
     */
    private short getChallenge(short len) {
        if (len > CHALLENGES_MAX_LENGTH)
            ISOException.throwIt(SW_WRONG_LENGTH);
        
        // Set the SSC used in Secure Messaging if the size of the requested 
        // challenge is equal to the size of the SSC
        if(len == OpenPGPSecureMessaging.SSC_SIZE) {
            random.generateData(sm.ssc, _0, len);
            sm.ssc_set[0] = true;
        }
        
        return len;
    }

    /**
     * (INS CA)
     * Output the data specified with tag.
     * 
     * @param tag Tag of the requested data
     */
    private short getData(short tag) {
        short offset = 0;

        switch (tag) {
            // 4F - Application identifier (AID)
            case (short) 0x004F:
                return JCSystem.getAID().getBytes(buffer, _0);

            // 5E - Login data
            case (short) 0x005E:
                return Util.arrayCopyNonAtomic(loginData, _0, buffer, _0, loginData_length);

            // 5F50 - URL
            case (short) 0x5F50:
                return Util.arrayCopyNonAtomic(url, _0, buffer, _0, url_length);

            // 5F52 - Historical bytes
            case (short) 0x5F52:
                return Util.arrayCopyNonAtomic(HISTORICAL, _0, buffer, _0, (short)HISTORICAL.length);

            // 65 - Cardholder Related Data
            case (short) 0x0065:
                buffer[offset++] = 0x65;
                buffer[offset++] = 0x0;

                // 5B - Name
                buffer[offset++] = 0x5B;
                buffer[offset++] = (byte) name_length;
                offset = Util.arrayCopyNonAtomic(name, _0, buffer, offset, name_length);

                // 5F2D - Language
                buffer[offset++] = 0x5F;
                buffer[offset++] = 0x2D;
                buffer[offset++] = (byte) lang_length;
                offset = Util.arrayCopyNonAtomic(lang, _0, buffer, offset, lang_length);

                // 5F35 - Sex
                buffer[offset++] = 0x5F;
                buffer[offset++] = 0x35;
                buffer[offset++] = 0x01;
                buffer[offset++] = sex;

                // Set length for combined data
                buffer[1] = (byte) (offset - 2);

                return offset;

            // 6E - Application Related Data
            case (short) 0x006E:
                buffer[offset++] = 0x6E;
                // Total length assumed to be >= 128 and < 256
                buffer[offset++] = (byte) 0x81;
                buffer[offset++] = 0;

                // 4F - AID
                buffer[offset++] = 0x4F;
                byte len = JCSystem.getAID().getBytes(buffer, (short)(offset + 1));
                buffer[offset++] = len;
                offset += len;

                // 5F52 - Historical bytes
                buffer[offset++] = 0x5F;
                buffer[offset++] = 0x52;
                buffer[offset++] = (byte) HISTORICAL.length;
                offset = Util.arrayCopyNonAtomic(HISTORICAL, _0, buffer, offset, (short) HISTORICAL.length);

                // 73 - Discretionary data objects
                buffer[offset++] = 0x73;
                buffer[offset++] = 0x0;

                // C0 - Extended capabilities
                buffer[offset++] = (byte) 0xC0;
                buffer[offset++] = (byte) EXTENDED_CAP.length;
                offset = Util.arrayCopyNonAtomic(EXTENDED_CAP, _0, buffer, offset, (short) EXTENDED_CAP.length);

                // C1 - Algorithm attributes signature
                buffer[offset++] = (byte) 0xC1;
                buffer[offset++] = (byte) 0x06;
                offset = sig_key.getAttributes(buffer, offset);

                // C2 - Algorithm attributes decryption
                buffer[offset++] = (byte) 0xC2;
                buffer[offset++] = (byte) 0x06;
                offset = dec_key.getAttributes(buffer, offset);

                // C3 - Algorithm attributes authentication
                buffer[offset++] = (byte) 0xC3;
                buffer[offset++] = (byte) 0x06;
                offset = auth_key.getAttributes(buffer, offset);

                // C4 - PW1 Status bytes
                buffer[offset++] = (byte) 0xC4;
                buffer[offset++] = 0x07;
                buffer[offset++] = pw1_status;
                buffer[offset++] = PW1_MAX_LENGTH;
                buffer[offset++] = RC_MAX_LENGTH;
                buffer[offset++] = PW3_MAX_LENGTH;
                buffer[offset++] = pw1.getTriesRemaining();
                buffer[offset++] = rc.getTriesRemaining();
                buffer[offset++] = pw3.getTriesRemaining();

                // C5 - Fingerprints sign, dec and auth keys
                buffer[offset++] = (byte) 0xC5;
                buffer[offset++] = (short) 60;
                offset = sig_key.getFingerprint(buffer, offset);
                offset = dec_key.getFingerprint(buffer, offset);
                offset = auth_key.getFingerprint(buffer, offset);

                // C6 - Fingerprints CA 1, 2 and 3
                buffer[offset++] = (byte) 0xC6;
                buffer[offset++] = (short) 60;
                offset = Util.arrayCopyNonAtomic(ca1_fp, _0, buffer, offset, (short) 20);
                offset = Util.arrayCopyNonAtomic(ca2_fp, _0, buffer, offset, (short) 20);
                offset = Util.arrayCopyNonAtomic(ca3_fp, _0, buffer, offset, (short) 20);

                // CD - Generation times of public key pair
                buffer[offset++] = (byte) 0xCD;
                buffer[offset++] = (short) 12;
                offset = sig_key.getTime(buffer, offset);
                offset = dec_key.getTime(buffer, offset);
                offset = auth_key.getTime(buffer, offset);

                // Set length of combined data
                buffer[2] = (byte) (offset - 3);

                return offset;

            // 7A - Security support template
            case (short) 0x007A:
                buffer[offset++] = 0x7A;
                buffer[offset++] = (byte) 0x05;

                // 93 - Digital signature counter
                buffer[offset++] = (byte) 0x93;
                buffer[offset++] = 0x03;
                offset = Util.arrayCopyNonAtomic(ds_counter, _0, buffer, offset, (short) 3);

                return offset;

            // 7F21 - Cardholder Certificate
            case (short) 0x7F21:
                // Use buffer since certificate may be longer than RESPONSE_MAX_LENGTH
                buffer[offset++] = 0x7F;
                buffer[offset++] = 0x21;

                if (cert_length < 128) {
                    buffer[offset++] = (byte) cert_length;
                } else if (cert_length < 256) {
                    buffer[offset++] = (byte) 0x81;
                    buffer[offset++] = (byte) cert_length;
                } else {
                    buffer[offset++] = (byte) 0x82;
                    Util.setShort(buffer, offset, cert_length);
                    offset += 2;
                }

                offset = Util.arrayCopyNonAtomic(cert, _0, buffer, offset, cert_length);

                return offset;

            // C4 - PW Status Bytes
            case (short) 0x00C4:
                buffer[offset++] = pw1_status;
                buffer[offset++] = PW1_MAX_LENGTH;
                buffer[offset++] = RC_MAX_LENGTH;
                buffer[offset++] = PW3_MAX_LENGTH;
                buffer[offset++] = pw1.getTriesRemaining();
                buffer[offset++] = rc.getTriesRemaining();
                buffer[offset++] = pw3.getTriesRemaining();

                return offset;

            default:
                ISOException.throwIt(SW_RECORD_NOT_FOUND);
            }
        
        return offset;
    }

    /**
     * (INS DA)
     * Write the data specified using tag.
     * Before using this method PW3 has to be verified.
     * 
     * @param tag Tag of the requested data
     */
    private void putData(short tag) {
        if (!pw3.isValidated())
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);

        switch (tag) {
        // 5B - Name
        case (short) 0x005B:
            if (in_received > name.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            name_length = Util.arrayCopy(buffer, _0, name, _0, in_received);
            break;

        // 5E - Login data
        case (short) 0x005E:
            if (in_received > loginData.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            loginData_length = Util.arrayCopy(buffer, _0, loginData, _0,
                    in_received);
            break;

        // 5F2D - Language preferences
        case (short) 0x5F2D:
            if (in_received > lang.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            lang_length = Util.arrayCopy(buffer, _0, lang, _0, in_received);
            break;

        // 5F35 - Sex
        case (short) 0x5F35:
            if (in_received != 1)
                ISOException.throwIt(SW_WRONG_LENGTH);

            // Check for valid values
            if (buffer[0] != (byte) 0x31 && buffer[0] != (byte) 0x32
                    && buffer[0] != (byte) 0x39)
                ISOException.throwIt(SW_WRONG_DATA);

            sex = buffer[0];
            break;

        // 5F50 - URL
        case (short) 0x5F50:
            if (in_received > url.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            url_length = Util.arrayCopy(buffer, _0, url, _0, in_received);
            break;

        // 7F21 - Cardholder certificate
        case (short) 0x7F21:
            if (in_received > cert.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            cert_length = Util.arrayCopy(buffer, _0, cert, _0, in_received);
            break;

        // C4 - PW Status Bytes
        case (short) 0x00C4:
            if (in_received != 1)
                ISOException.throwIt(SW_WRONG_LENGTH);

            // Check for valid values
            if (buffer[0] != (byte) 0x0 && buffer[0] != (byte) 0x01)
                ISOException.throwIt(SW_WRONG_DATA);

            pw1_status = buffer[0];
            break;

        // C7 - Fingerprint signature key
        case (short) 0x00C7:
            if (in_received != PGPKey.FP_SIZE)
                ISOException.throwIt(SW_WRONG_LENGTH);

            sig_key.setFingerprint(buffer, _0);
            break;

        // C8 - Fingerprint decryption key
        case (short) 0x00C8:
            if (in_received != PGPKey.FP_SIZE)
                ISOException.throwIt(SW_WRONG_LENGTH);

            dec_key.setFingerprint(buffer, _0);
            break;

        // C9 - Fingerprint authentication key
        case (short) 0x00C9:
            if (in_received != PGPKey.FP_SIZE)
                ISOException.throwIt(SW_WRONG_LENGTH);

            auth_key.setFingerprint(buffer, _0);
            break;

        // CA - Fingerprint Certification Authority 1
        case (short) 0x00CA:
            if (in_received != ca1_fp.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            Util.arrayCopy(buffer, _0, ca1_fp, _0, in_received);
            break;

        // CB - Fingerprint Certification Authority 2
        case (short) 0x00CB:
            if (in_received != ca2_fp.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            Util.arrayCopy(buffer, _0, ca2_fp, _0, in_received);
            break;

        // CC - Fingerprint Certification Authority 3
        case (short) 0x00CC:
            if (in_received != ca3_fp.length)
                ISOException.throwIt(SW_WRONG_LENGTH);

            Util.arrayCopy(buffer, _0, ca3_fp, _0, in_received);
            break;

        // CE - Signature key generation date/time
        case (short) 0x00CE:
            if (in_received != 4)
                ISOException.throwIt(SW_WRONG_LENGTH);

            sig_key.setTime(buffer, _0);
            break;

        // CF - Decryption key generation date/time
        case (short) 0x00CF:
            if (in_received != 4)
                ISOException.throwIt(SW_WRONG_LENGTH);

            dec_key.setTime(buffer, _0);
            break;

        // D0 - Authentication key generation date/time
        case (short) 0x00D0:
            if (in_received != 4)
                ISOException.throwIt(SW_WRONG_LENGTH);

            auth_key.setTime(buffer, _0);
            break;

        // D3 - Resetting Code
        case (short) 0x00D3:
            if (in_received == 0) {
                rc_length = 0;
            } else if (in_received >= RC_MIN_LENGTH
                    && in_received <= RC_MAX_LENGTH) {
                JCSystem.beginTransaction();
                rc.update(buffer, _0, (byte) in_received);
                rc_length = (byte) in_received;
                JCSystem.commitTransaction();
            } else {
                ISOException.throwIt(SW_WRONG_LENGTH);
            }
            break;

        // D1 - SM-Key-ENC
        case (short) 0x00D1:
            sm.setSessionKeyEncryption(buffer, _0);
            break;
            
        // D2 - SM-Key-MAC
        case (short) 0x00D2:
            sm.setSessionKeyMAC(buffer, _0);
            break;
            
        // F4 - SM-Key-Container
        case (short) 0x00F4:
            short offset = 0;
            short key_len; 
            // Set encryption key
            if(buffer[offset++] == (byte)0xD1) {
                key_len = (short)(buffer[offset++] & 0x7F);
                sm.setSessionKeyEncryption(buffer, offset);
                offset += key_len;
            }

            // Set MAC key            
            if(buffer[offset++] == (byte)0xD2) {
                key_len = (short)(buffer[offset++] & 0x7F);
                sm.setSessionKeyMAC(buffer, offset);
                offset += key_len;
            }
            break;
            
        default:
            ISOException.throwIt(SW_RECORD_NOT_FOUND);
            break;
        }
    }

    /**
     * EXPERIMENTAL: Provide functionality for importing keys.
     */
    private void importKey() {
        if (!pw3.isValidated())
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);        
        
        short offset = 0;

        // Check for tag 4D
        if (buffer[offset++] != 0x4D)
            ISOException.throwIt(SW_DATA_INVALID);

        // Length of 4D
        offset += getLengthBytes(getLength(buffer, offset));

        // Get key for Control Reference Template
        PGPKey i_key = sig_key;
        switch (buffer[offset++]) {
            case (byte) 0xB6: /*i_key = sig_key*/ break;
            case (byte) 0xB8: i_key = dec_key;    break;
            case (byte) 0xA4: i_key = auth_key;   break;
            default: ISOException.throwIt(SW_UNKNOWN);
        }

        // Skip empty length of CRT
        offset++;

        // Check for tag 7F48
        if (!(buffer[offset++] == 0x7F && buffer[offset++] == 0x48))
            ISOException.throwIt(SW_DATA_INVALID);
        short len_template = getLength(buffer, offset);
        offset += getLengthBytes(len_template);

        short offset_data = (short) (offset + len_template);

        if (buffer[offset++] != (byte) 0x91)
            ISOException.throwIt(SW_DATA_INVALID);
        short len_e = getLength(buffer, offset);
        offset += getLengthBytes(len_e);

        if (buffer[offset++] != (byte) 0x92)
            ISOException.throwIt(SW_DATA_INVALID);
        short len_p = getLength(buffer, offset);
        offset += getLengthBytes(len_p);

        if (buffer[offset++] != (byte) 0x93)
            ISOException.throwIt(SW_DATA_INVALID);
        short len_q = getLength(buffer, offset);
        offset += getLengthBytes(len_q);

        if (buffer[offset++] != (byte) 0x94)
            ISOException.throwIt(SW_DATA_INVALID);
        short len_pq = getLength(buffer, offset);
        offset += getLengthBytes(len_pq);

        if (buffer[offset++] != (byte) 0x95)
            ISOException.throwIt(SW_DATA_INVALID);
        short len_dp1 = getLength(buffer, offset);
        offset += getLengthBytes(len_dp1);

        if (buffer[offset++] != (byte) 0x96)
            ISOException.throwIt(SW_DATA_INVALID);
        short len_dq1 = getLength(buffer, offset);
        offset += getLengthBytes(len_dq1);

        if (!(buffer[offset_data++] == 0x5F && buffer[offset_data++] == 0x48))
            ISOException.throwIt(SW_DATA_INVALID);
        offset_data += getLengthBytes(getLength(buffer, offset_data));

        offset_data += len_e;

        ((RSAPrivateCrtKey) i_key.key.getPrivate()).setP(buffer, offset_data, len_p);
        offset_data += len_p;

        ((RSAPrivateCrtKey) i_key.key.getPrivate()).setQ(buffer, offset_data, len_q);
        offset_data += len_q;
        
        ((RSAPrivateCrtKey) i_key.key.getPrivate()).setPQ(buffer, offset_data, len_pq);
        offset_data += len_pq;
        
        ((RSAPrivateCrtKey) i_key.key.getPrivate()).setDP1(buffer, offset_data, len_dp1);
        offset_data += len_dp1;

        ((RSAPrivateCrtKey) i_key.key.getPrivate()).setDQ1(buffer, offset_data, len_dq1);
        offset_data += len_dq1;
    }
    
    /**
     * Send next block of data in buffer. Used for sending data in <buffer>
     * 
     * @param apdu
     * @param status Status to send
     */
    private void sendNext(APDU apdu, short status) {
        byte[] buf = APDU.getCurrentAPDUBuffer();
        apdu.setOutgoing();
        
        // Determine maximum size of the messages
        short max_length;
        if(sm_success) {
            max_length = RESPONSE_SM_MAX_LENGTH;
        }
        else {
            max_length = RESPONSE_MAX_LENGTH;
        }
        
        Util.arrayCopyNonAtomic(buffer, out_sent, buf, _0, max_length);

        short len;
        
        if (out_left > max_length) {
            len = max_length;
            
            // Compute byte left and sent
            out_left -= max_length;
            out_sent += max_length;
            
            // Determine new status word
            if (out_left > max_length) {
                status = (short) (SW_BYTES_REMAINING_00 | max_length);
            } else {
                status = (short) (SW_BYTES_REMAINING_00 | out_left);
            }
        }
        else {
            len = out_left;
            
            // Reset buffer
            out_sent = 0;
            out_left = 0;            
        }
        
        // If SM is used, wrap response
        if(sm_success) {
            len = sm.wrapResponseAPDU(buf, _0, len, status);
        }
                
        // Send data in buffer
        apdu.setOutgoingLength(len);
        apdu.sendBytes(_0, len);

        // Send status word
        if(status != SW_NO_ERROR)
            ISOException.throwIt(status);
    }

    
    ///// Utility functions /////
    
    // Get length of TLV element.
    private short getLength(byte[] data, short offset) {
        short len = 0;

        if ((data[offset] & (byte) 0x80) == (byte) 0x0) {
            len = data[offset];
        } else if ((data[offset] & (byte) 0x7F) == (byte) 0x01) {
            len = (short)(0xFF & data[(short) (offset + 1)]);
        } else if ((data[offset] & (byte) 0x7F) == (byte) 0x02) {
            len = Util.makeShort(data[(short) (offset + 1)], data[(short) (offset + 2)]);
        } else {
            ISOException.throwIt(SW_UNKNOWN);
        }

        return len;
    }

    // Get number of bytes needed to represent length for TLV element.
    private short getLengthBytes(short length) {
        if (length <= 127)
            return 1;
        else if (length <= 255)
            return 2;
        else
            return 3;
    }
}
