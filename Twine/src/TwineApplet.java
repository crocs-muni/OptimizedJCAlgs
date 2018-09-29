/*
 * TODO CHANGE IDs
 * PACKAGEID: 41 45 47 49 53 3A         //
 * APPLETID: 41 45 47 49 53 3A 50 04 47 ./
 */
package applets;

import javacard.framework.*;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 *
 * @author Matej Evin
 * 6th March 2018
 */
public class TwineApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET              = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_TWINE_ENCRYPT             = (byte) 0x61;
    
    //Constants
    final static short ARRAY_LENGTH                 = (short) 0xff;
    
    //Error codes
    final static short SW_OBJECT_NOT_AVAILABLE      = (short) 0x6711;

    private TwineCipher m_twine = null;           //message digest
    private DESKey m_des = null;
        
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray1[] = null;
    private byte m_ramArray2[] = null;

    /**
     * AegisApplet constructor
     * Only this class's install method should create the applet object.
     */
    protected TwineApplet(byte[] buffer, short offset, byte length)
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
            m_ramArray2 = JCSystem.makeTransientByteArray((short) 0xff, JCSystem.CLEAR_ON_DESELECT);

            m_twine = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_128);
            m_des = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);

            // update flag
            isOP2 = true;

        } else {}
            register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // no parameters needed
        new TwineApplet(bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {
        // <PUT YOUR DESELECTION ACTION HERE>
        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
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
                case INS_TWINE_ENCRYPT:
                    Twine_encrypt(apdu);
                break;
                
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void Twine_encrypt(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        m_ramArray1[0] = (byte) 0x00;
        m_ramArray1[1] = (byte) 0x11;
        m_ramArray1[2] = (byte) 0x22;
        m_ramArray1[3] = (byte) 0x33;
        m_ramArray1[4] = (byte) 0x44;
        m_ramArray1[5] = (byte) 0x55;
        m_ramArray1[6] = (byte) 0x66;
        m_ramArray1[7] = (byte) 0x77;
        m_ramArray1[8] = (byte) 0x88;
        m_ramArray1[9] = (byte) 0x99;
        m_ramArray1[10] = (byte) 0xAA;
        m_ramArray1[11] = (byte) 0xBB;
        m_ramArray1[12] = (byte) 0xCC;
        m_ramArray1[13] = (byte) 0xDD;
        m_ramArray1[14] = (byte) 0xEE;
        m_ramArray1[15] = (byte) 0xFF;

        //init des key
        if (!m_des.isInitialized())
            m_des.setKey(m_ramArray1, (short) 0);
        
        m_twine.init(m_des, Cipher.MODE_ENCRYPT);
        
        //plaintext
        //3a 8a 2c 2b 2d d5 4e d2 90 00
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
        
        
        //Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArray1, (short) 0, dataLen);
        short ret = m_twine.doFinal(m_ramArray1, (short) 0, (short) 16, apdubuf, ISO7816.OFFSET_CDATA);
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, ret);

    }
}