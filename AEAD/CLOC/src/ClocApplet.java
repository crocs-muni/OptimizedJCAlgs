/*
 * PACKAGEID: 43 4C 4F 43 4B 3A  // CLOC:
 * APPLETID: 43 4C 4F 43 4B 3A 50 04 47   // CLOC:PKG
 */
package cloc;

import javacard.framework.*;

/**
 *
 * @author rajesh
 */
public class ClocApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET               = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_CLOCENCRYPTION             = (byte) 0x61;
    final static byte INS_CLOCDECRYPTION             = (byte) 0x62;

    final static short ARRAY_LENGTH                  = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH              = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;

    private   ClocCore       mycloc = null;           //CLOC engine
    
    //CLOC Parameters-- Encryption
     byte[] AD = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x09, (byte)0x00, (byte)0x02};
     short ADLEN = (short)AD.length;
     byte[] NSEC = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     byte[] NPUB = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     byte[] KEY = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
     short KEYLEN = (short)KEY.length;
     
     //CLOC Parameters-- Decryption
     byte[] AD1 = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x09, (byte)0x00, (byte)0x02};
     short ADLEN1 = (short)AD1.length;
     byte[] NSEC1 = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     byte[] NPUB1 = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     byte[] KEY1 = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
     short KEYLEN1 = (short)KEY1.length;
     
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArrayPt[] = null;
    private byte m_ramArrayCt[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * ClocApplet constructor
     * Only this class's install method should create the applet object.
     */
    protected ClocApplet(byte[] buffer, short offset, byte length)
    {
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

           // go to proprietary data
            dataOffset++;

            // PERSISTENT BUFFER IN EEPROM
            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArrayPt = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            m_ramArrayCt = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            //Create ASCON OBJECT
            mycloc = new ClocCore();
            
            // update flag
            isOP2 = true;

        } else {}
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        new ClocApplet (bArray, bOffset, bLength);
    }

    public boolean select()
    {
        return true;
    }

    public void deselect()
    {
        return;
    }

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
                case INS_CLOCENCRYPTION: CLOCEncryption(apdu); break;
                case INS_CLOCDECRYPTION: CLOCDecryption(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void CLOCEncryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
            
        // Copy message to m_ramArrayPt for encryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArrayPt, (short)0, dataLen);
        
        mycloc.init(NSEC, NPUB, KEY, KEYLEN);
        // CLOC Encryption
        mycloc.encrypt(m_ramArrayPt, dataLen, m_ramArrayCt, AD, ADLEN);
        
        // Copy ciphertext
        Util.arrayCopyNonAtomic(m_ramArrayCt, (short)0, apdubuf, (short)0, (short)(dataLen+8));
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+8));
    }

    
    public void CLOCDecryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        // Copy cipher to m_ramArrayCt for decryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArrayCt, (short)0, dataLen);
        
        mycloc.init(NSEC1, NPUB1, KEY1, KEYLEN1);
        // CLOC Decryption
        mycloc.decrypt(m_ramArrayCt, dataLen, m_ramArrayPt, AD1, ADLEN1);
        
        // Copy retrieved message (plaintext)
        Util.arrayCopyNonAtomic(m_ramArrayPt, (short)0, apdubuf, (short)0, (short)(dataLen-8));
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen-8));
    }
}
