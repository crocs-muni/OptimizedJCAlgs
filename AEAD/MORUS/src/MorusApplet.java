/*
 * PACKAGEID: 4D 4F 52 55 53 3A  // MORUS:
 * APPLETID: 4D 4F 52 55 53 3A 50 04 47   // MORUS:PKG
 */
package morus;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;


/**
 *
 * @author rajesh
 */
public class MorusApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET               = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_MORUSENCRYPTION            = (byte) 0x61;
    final static byte INS_MORUSDECRYPTION            = (byte) 0x62;

    final static short ARRAY_LENGTH                  = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH              = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;

    private MorusCore m_morus = null;
    
    //ASCON Parameters-- Encryption
     public byte[] AD = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02};
     public short ADLEN = (short)AD.length;
     public byte[] NSEC = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     public byte[] NPUB = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     public byte[] KEY = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
    
     //ASCON Parameters-- Decryption
     public byte[] AD1 = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02};
     public short ADLEN1 = (short)AD1.length;
     public byte[] NSEC1 = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     public byte[] NPUB1 = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     public byte[] KEY1 = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
    
     
    // TEMPORARRY ARRAY IN RAM
    private   byte           m_ramArray[] = null;

    /**
     * AezApplet constructor
     * Only this class's install method should create the applet object.
     */
    protected MorusApplet(byte[] buffer, short offset, byte length)
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
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            //Create ASCON OBJECT
            m_morus = new MorusCore();
            
            // update flag
            isOP2 = true;

        } else {}
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        new MorusApplet (bArray, bOffset, bLength);
    }

    public boolean select()
    {
        return true;
    }

    public void deselect() {}

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
                case INS_MORUSENCRYPTION: MORUSEncryption(apdu); break;
                case INS_MORUSDECRYPTION: MORUSDecryption(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void MORUSEncryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        // Copy message to m_ramArray for encryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArray, (short)0, dataLen);
            
        m_morus.init(NSEC, NPUB, KEY);
        
        // MORUS Encryption
        m_morus.encrypt(m_ramArray, (short)0, m_ramArray, dataLen, AD, ADLEN);
        Util.arrayCopyNonAtomic(m_ramArray, (short)0, apdubuf, (short)0, (short)(dataLen+16));
            
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+16));
    }

    
    public void MORUSDecryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        // Copy cipher to m_ramArray for decryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArray, (short)0, dataLen);
        
        m_morus.init(NSEC1, NPUB1, KEY1);
        // MORUS Decryption
        m_morus.decrypt(m_ramArray, dataLen, m_ramArray, (short)0, AD1, ADLEN1);
        Util.arrayCopyNonAtomic(m_ramArray, (short)0, apdubuf, (short)0, (short)(dataLen-16));
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen-16));
    }    
}
