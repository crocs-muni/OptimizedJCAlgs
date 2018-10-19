/*
 * TODO CHANGE IDs
 * PACKAGEID: 41 45 47 49 53 3A         //
 * APPLETID: 41 45 47 49 53 3A 50 04 47 ./
 */
package applets;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 *
 * @author Matej Evin
 * 6th March 2018
 */
public class ZorroApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET              = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ZORRO_ENCRYPT             = (byte) 0x61;
    
    //Constants
    final static short ARRAY_LENGTH                 = (short) 0xff;
    
    //Error codes
    final static short SW_OBJECT_NOT_AVAILABLE      = (short) 0x6711;

    private Cipher m_zorro = null;
    private AESKey m_aes   = null;
        
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray1[] = null;
    
    private final byte[] ZORRO_KEY = {
        (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33,
        (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77,
        (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB,
        (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF };

    /**
     * AegisApplet constructor
     * Only this class's install method should create the applet object.
     */
    protected ZorroApplet(byte[] buffer, short offset, byte length)
    {
	
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

           // go to proprietary data
            dataOffset++;

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray1 = JCSystem.makeTransientByteArray((short) 0xff, JCSystem.CLEAR_ON_DESELECT);

            m_aes = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            m_aes.setKey(ZORRO_KEY, (short) 0);
            
            m_zorro = ZorroCipher.getInstance();
            m_zorro.init(m_aes, Cipher.MODE_ENCRYPT);

            // update flag
            isOP2 = true;

        } else {}
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        new ZorroApplet(bArray, bOffset, bLength);
    }

    public boolean select()
    {
        return true;
    }

    public void deselect() { }

    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        
        // ignore the applet select command dispatched to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {               
                case INS_ZORRO_ENCRYPT:
                    Zorro_encrypt(apdu);
                break;
                
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void Zorro_encrypt(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        //test vector:
        // key: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
        // pt:  01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef
        // ct:  11 52 00 a7 25 d1 4c ad 9b f8 0b dd 79 f6 94 39 (90 00)
        
        //plaintext
        m_ramArray1[0] = (byte) 0x01;
        m_ramArray1[1] = (byte) 0x23;
        m_ramArray1[2] = (byte) 0x45;
        m_ramArray1[3] = (byte) 0x67;
        m_ramArray1[4] = (byte) 0x89;
        m_ramArray1[5] = (byte) 0xab;
        m_ramArray1[6] = (byte) 0xcd;
        m_ramArray1[7] = (byte) 0xef;
        
        m_ramArray1[8] = (byte)  0x01;
        m_ramArray1[9] = (byte)  0x23;
        m_ramArray1[10] = (byte) 0x45;
        m_ramArray1[11] = (byte) 0x67;
        m_ramArray1[12] = (byte) 0x89;
        m_ramArray1[13] = (byte) 0xab;
        m_ramArray1[14] = (byte) 0xcd;
        m_ramArray1[15] = (byte) 0xef;
        
        short ret = m_zorro.doFinal(m_ramArray1, (short) 0, (short) 16, apdubuf, ISO7816.OFFSET_CDATA);
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, ret);

    }
}
