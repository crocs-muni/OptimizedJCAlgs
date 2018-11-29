/*
 * PACKAGEID: 41 45 47 49 53 3A  // AEGIS:
 * APPLETID: 41 45 47 49 53 3A 50 04 47   // AEGIS:PKG
 */
package aegis;

//import javacard.framework.*;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;


/**
 *
 * @author rajesh
 * @review matej
 */
public class AegisApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET               = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_AEGISENCRYPTION            = (byte) 0x61;
    final static byte INS_AEGISDECRYPTION            = (byte) 0x62;

    final static short ARRAY_LENGTH                  = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH              = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;

    private   AegisCore  myaegis = null;           //AEGIS engine
    
    //AEGIS Parameters-- Encryption
     byte[] AD = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02};
     short ADLEN = (short)AD.length;
     byte[] NSEC = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     byte[] NPUB = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     byte[] KEY = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
     short KEYLEN = (short)KEY.length;
     
     /*AEGIS Parameters-- Decryption
     byte[] AD1 = {(byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x05, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02, (byte)0x09, (byte)0x09, (byte)0x00, (byte)0x02};
     short ADLEN1 = (short)AD1.length;
     byte[] NSEC1 = {(byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x01};
     byte[] NPUB1 = {(byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x02};
     byte[] KEY1 = {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06};
     short KEYLEN1 = (short)KEY1.length;*/
     
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArrayPt[] = null;     //plaintext array
    private byte m_ramArrayCt[] = null;     //ciphertext array

    //constructor
    protected AegisApplet(byte[] buffer, short offset, byte length)
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

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArrayPt = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            m_ramArrayCt = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            //Create AEGIS OBJECT
            myaegis = new AegisCore();
            
            // update flag
            isOP2 = true;

        } else {}
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        new AegisApplet(bArray, bOffset, bLength);
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
                case INS_AEGISENCRYPTION: AEGISEncryption(apdu); break;
                case INS_AEGISDECRYPTION: AEGISDecryption(apdu); break;
                default :
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED);
                break ;

            }
        }
        else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void AEGISEncryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        // Copy message to m_ramArrayPt for encryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArrayPt, (short)0, dataLen);
        
        myaegis.init(NSEC, NPUB, KEY, KEYLEN);
        
        // AEGIS Encryption
        myaegis.encrypt(m_ramArrayCt, (short)0, m_ramArrayPt, dataLen, AD, ADLEN);
        
        // Copy ciphertext
        Util.arrayCopyNonAtomic(m_ramArrayCt, (short)0, apdubuf, (short)0, (short)(dataLen+16));
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+16));
    }

    
    public void AEGISDecryption(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        // Copy cipher to m_ramArrayCt for decryption
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArrayCt, (short)0, dataLen);
        
        myaegis.init(NSEC, NPUB, KEY, KEYLEN);
        // AEGIS Decryption
        myaegis.decrypt(m_ramArrayCt, dataLen, m_ramArrayPt, (short)0, AD, ADLEN);
        
        // Copy retrieved message (plaintext)
        Util.arrayCopyNonAtomic(m_ramArrayPt, (short)0, apdubuf, (short)0, (short)(dataLen-16));
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, (short)(dataLen-16));
    }
}
