/*
 * TODO CHANGE IDs
 * PACKAGEID: 41 45 47 49 53 3A         //
 * APPLETID: 41 45 47 49 53 3A 50 04 47 ./
 */
package applets;

import javacard.framework.*;
import javacard.security.MessageDigest;

/**
 *
 * @author Matej Evin
 * 6th March 2018
 */
public class Sha3Applet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET              = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_MESSAGE_DIGEST            = (byte) 0x61;
    
    //Constants
    final static short ARRAY_LENGTH                 = (short) 0xff;
    
    //Error codes
    final static short SW_OBJECT_NOT_AVAILABLE      = (short) 0x6711;

    private   MessageDigest m_keccak = null;      //Keccak message digest
    //private   MessageDigest m_sha2 = null;      //sha2 message digest
        
    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray1[] = null;

    /**
     * AegisApplet constructor
     * Only this class's install method should create the applet object.
     */
    protected Sha3Applet(byte[] buffer, short offset, byte length)
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

            //compare with sha2
            //m_sha2 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

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
        new Sha3Applet(bArray, bOffset, bLength);
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
                case 0x00: computeKeccak(apdu, Keccak.ALG_SHA3_224); break;
                case 0x01: computeKeccak(apdu, Keccak.ALG_SHA3_256); break;
                case 0x02: computeKeccak(apdu, Keccak.ALG_SHA3_384); break;
                case 0x03: computeKeccak(apdu, Keccak.ALG_SHA3_512); break;
                case 0x04: computeKeccak(apdu, Keccak.ALG_KECCAK_224); break;
                case 0x05: computeKeccak(apdu, Keccak.ALG_KECCAK_256); break;
                case 0x06: computeKeccak(apdu, Keccak.ALG_KECCAK_384); break;
                case 0x07: computeKeccak(apdu, Keccak.ALG_KECCAK_512); break;
                case 0x08: computeKeccak(apdu, Keccak.ALG_SHAKE_128); break;
                case 0x09: computeKeccak(apdu, Keccak.ALG_SHAKE_256); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    
    public void computeKeccak(APDU apdu, byte algorithm){
        //Create Keccak OBJECT
        m_keccak = Keccak.getInstance(algorithm);
        m_keccak.reset();
//        ((Keccak)m_keccak).setShakeDigestLength((short)128); //Optional function to set shake return bytes to 128 bytes

        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_ramArray1, (short) 0, dataLen);
        short ret1 = m_keccak.doFinal(m_ramArray1, (short) 0, dataLen, apdubuf, (short) 0);
        //short ret2 = m_sha2.doFinal(m_ramArray1, (short) 0, dataLen, apdubuf, (short) 0);
        
        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend((short)0, ret1);
    }
}
