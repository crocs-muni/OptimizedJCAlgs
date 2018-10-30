/*
 * TODO CHANGE IDs
 * PACKAGEID: 41 45 47 49 53 3A         //
 * APPLETID: 41 45 47 49 53 3A 50 04 47 ./
 */
package applets;

import javacard.framework.*;

/**
 *
 * @author Matej Evin
 * 6th March 2018
 */
public class Pbkdf2Applet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET              = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_MESSAGE_DIGEST            = (byte) 0x61;
    
    //Constants
    final static short ARRAY_LENGTH                 = (short) 0xff;
    
    //Error codes
    final static short SW_OBJECT_NOT_AVAILABLE      = (short) 0x6711;

    private   PBKDF2  m_pbkdf2 = null;           //message digest
        
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray1[] = null;
    private byte m_ramArray2[] = null;
    private byte m_ramArray3[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * AegisApplet constructor
     * Only this class's install method should create the applet object.
     */
    protected Pbkdf2Applet(byte[] buffer, short offset, byte length)
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

            // PERSISTENT BUFFER IN EEPROM
            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray1 = JCSystem.makeTransientByteArray((short) 0xff, JCSystem.CLEAR_ON_DESELECT);
            m_ramArray2 = JCSystem.makeTransientByteArray((short) 0xff, JCSystem.CLEAR_ON_DESELECT);
            m_ramArray3 = JCSystem.makeTransientByteArray((short) 0xff, JCSystem.CLEAR_ON_DESELECT);

            m_pbkdf2 = PBKDF2.getInstance(PBKDF2.ALG_SHA);

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
        //new Sha3Applet();
        new Pbkdf2Applet(bArray, bOffset, bLength);
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
                case INS_MESSAGE_DIGEST:
                    Pbkdf2(apdu);
                break;
                
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void Pbkdf2(APDU apdu){
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        //"password"
        m_ramArray1[0] = 0x70;
        m_ramArray1[1] = 0x61;
        m_ramArray1[2] = 0x73;
        m_ramArray1[3] = 0x73;
        m_ramArray1[4] = 0x77;
        m_ramArray1[5] = 0x6F;
        m_ramArray1[6] = 0x72;
        m_ramArray1[7] = 0x64;
        
        //"salt"
        m_ramArray2[0] = 0x73;
        m_ramArray2[1] = 0x61;
        m_ramArray2[2] = 0x6C;
        m_ramArray2[3] = 0x74;
        
        //Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArray1, (short) 0, dataLen);
        short ret = m_pbkdf2.doFinal(m_ramArray1, (short) 0, (short) 8,
                                     m_ramArray2, (short) 0, (short) 4,
                                     (short) 1,
                                     m_ramArray3, (short) 0);
        
        // SEND OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray3, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, ret);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, ret);
    }
}
