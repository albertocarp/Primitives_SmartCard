package sid;

import com.sun.javacard.impl.PackageEntry;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.crypto.Cipher;

public class TestApplet extends Applet 
			implements IConsts {
	private TestApplet()
	{	
		
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new TestApplet().register();
	}
	
	public void process(APDU apdu) throws ISOException {
		if (selectingApplet()) {
			return;
		}
		byte[] buf = apdu.getBuffer();
		if(buf[ISO7816.OFFSET_CLA] != IConsts.OFFSET_CLA_APPLICATION)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
		short read = apdu.setIncomingAndReceive();
		while(read < lc) {
		  read += apdu.receiveBytes(read);
		}
		switch (buf[ISO7816.OFFSET_INS]) 
		{
			case IConsts.OFFSET_INS_LIGHT:
				processLight(apdu);
				return;
			case IConsts.OFFSET_INS_SYSTEM:
				process(apdu);
				return;
			case IConsts.OFFSET_INS_UPROVE:
				processUprove(apdu);
				return;
			case IConsts.OFFSET_INS_TEST:
				processTest(apdu);
				return;
			case IConsts.OFFSET_INS_HASH:
				processHash(apdu);
				return;
			default:
				break;
		}
	}
	
	private void processUprove(APDU apdu) {
		
		byte[] buf = apdu.getBuffer();
		byte state = (buf[ISO7816.OFFSET_P1]);
		byte type = (buf[ISO7816.OFFSET_P2]);
		short count_data = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
		if(count_data < 0)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		UProve instance = UProve.getInstance();
		switch(state)
		{
			case CMD_SET_E_I:
			{
				if(count_data != instance.parameters.MAX_ATTR)
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				instance.setEi(buf,(short)(ISO7816.OFFSET_LC+1),instance.parameters.MAX_ATTR);
				break;
			}
			case CMD_FULL_TEST_DEBUG:
			{
				instance.run();
				break;
			}
			case  CMD_SET_PQG:
			{
				if(type == 0x00) // This is p
				{
					instance.setP(buf,(short)(ISO7816.OFFSET_LC+1),UProveParameters.PSIZE_BYTES);
					
				}
				if(type == 0x01) // This is q
				{
					instance.setQ(buf,(short)(ISO7816.OFFSET_LC+1),UProveParameters.QSIZE_BYTES);
				}
				if(type == 0x02) // This is p
				{
					instance.setG(buf,(short)(ISO7816.OFFSET_LC+1),UProveParameters.PSIZE_BYTES);
				}
				break;
			}
			case CMD_SET_UIDP:
			{
				instance.setUidp(buf, (short)(ISO7816.OFFSET_LC+1), count_data);
				break;
			}
			case CMD_GET_UIDP:
			{
				byte[] data = instance.getUidp();
				Util.arrayCopy(buf, (short)(ISO7816.OFFSET_LC+1), data,(short)0,(short)data.length);
				apdu.setOutgoingAndSend((short)(ISO7816.OFFSET_LC+1), (short)data.length);
				break;
			}
			case CMD_GET_PQG:
			{
				byte[] data = null;
				short length = 0;
				short offset = 0;;
				if(type == 0x00) // This is p
				{
					data = instance.parameters.sigma_r;
					offset =  0;
					length = UProveParameters.QSIZE_BYTES;
				}
				if(type == 0x01) // This is q
				{
					data = instance.parameters.sigma_r_prime;
					offset =  0;
					length = UProveParameters.QSIZE_BYTES;
				}
				if(type == 0x02) // This is g
				{
					data = instance.parameters.temp_ram;
					offset = 256;
					length = UProveParameters.PSIZE_BYTES;
				}
				Util.arrayCopy(data,offset,buf, (short)(ISO7816.OFFSET_LC+1),length);
				apdu.setOutgoingAndSend((short)(ISO7816.OFFSET_LC+1),length);
				break;
			}
			case CMD_SET_PUB_KEY:
			{
				if(count_data != UProveParameters.PSIZE_BYTES)
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				instance.setPubKey(buf, ISO7816.OFFSET_CDATA, count_data, type);
				break;
			}
			case CMD_GET_PUB_KEY:
			{
				byte[] data = instance.getPubKey(state);
				Util.arrayCopy(buf, (short)(ISO7816.OFFSET_LC+1), data,(short)0,(short)data.length);
				apdu.setOutgoingAndSend((short)(ISO7816.OFFSET_LC+1), (short)data.length);
				break;
			}
			case CMD_GET_ATTR_COUNT:	
			{
				Util.arrayCopy(buf, ISO7816.OFFSET_CDATA,instance.getAttrCount(), (short)0, (short)2);
				apdu.setOutgoingAndSend((short)(ISO7816.OFFSET_LC+1),(short)2);
				break;
			}
			case CMD_SET_ATTR_VAL:
			{
				if(type == 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				instance.setAtributeValue(buf,ISO7816.OFFSET_CDATA,UProveParameters.QSIZE_BYTES,(short)(type-1));
				break;
			}
			case CMD_SET_ATTR_VAL_PUBLIC:
			{
				if(type == 0)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				instance.setAtribute(buf,ISO7816.OFFSET_CDATA,UProveParameters.QSIZE_BYTES,count_data,(short)(type));
				break;
			}
			case CMD_PRECOMPUTE_INPUTS:
			{
				instance.computeXt();
				instance.calculateGamma();
				break;
			}
			case CMD_SET_PI:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			case CMD_SET_TI:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			case CMD_GET_PI:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				byte[] data = instance.getPI();
				Util.arrayCopy(buf, (short)(ISO7816.OFFSET_LC+1), data,(short)0,(short)data.length);
				apdu.setOutgoingAndSend((short)(ISO7816.OFFSET_LC+1), (short)data.length);
				break;
			}
			case CMD_GET_TI:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				byte[] data = instance.getTI();
				Util.arrayCopy(buf, (short)(ISO7816.OFFSET_LC+1), data,(short)0,(short)data.length);
				apdu.setOutgoingAndSend((short)(ISO7816.OFFSET_LC+1), (short)data.length);
				break;
			}
			case CMD_GET_GAMMA:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				byte[] data = instance.parameters.gamma;
				Util.arrayCopy(buf, (short)(ISO7816.OFFSET_LC+1), data,(short)0,(short)data.length);
				apdu.setOutgoingAndSend((short)(ISO7816.OFFSET_LC+1), (short)data.length);
				break;
			}
			case CMD_TEST_FIRST_MESSAGE:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				instance.issuerPrecomputation();
				break;
			}
			case CMD_TEST_SECOND_MESSAGE:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				instance.generateSecondMessage();
				break;
			}
			case CMD_TEST_THIRD_MESSAGE:
			{
				if(type != 0x00)
					ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				instance.generateThirdMessage();
				break;
			}
		}
	}

	private void processLight(APDU apdu)
	{
		 //cla and ins are proccessed
		byte[] buf = apdu.getBuffer();
		byte state = (buf[ISO7816.OFFSET_P1]);
		byte type = (buf[ISO7816.OFFSET_P2]);
		byte count_data = buf[ISO7816.OFFSET_LC];
		if(count_data == 0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		short len_data = -1;
		switch(state)
		{
		    case OFFSET_P1_ENC:
		    	switch(type)
		    	{
		    		case TWINE_CIPHER_80:
		    			TwineCipher m_instance = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80);
		    			len_data  = m_instance.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case TWINE_CIPHER_128:
		    			TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80); //TODO change that
		    			return;
		    		case LBLOCK_CIPHER:
		    			LBlockCipher m_instance_lblock= LBlockCipher.getInstance();
		    			len_data  = m_instance_lblock.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case ZORRO_CIPHER:
		    			ZorroCipher m_instance_zorro = ZorroCipher.getInstance();
		    			len_data  = m_instance_zorro.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case PICOLLO_CIPHER:
		    			PicolloCipher m_instance_picollo = PicolloCipher.getInstance();
		    			len_data  = m_instance_picollo.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case RECTANGLE_CIPHER:
		    			RectangleCipher m_instance_rectangle = RectangleCipher.getInstance();
		    			len_data  = m_instance_rectangle.process(OFFSET_P1_ENC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		default:
		    			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		    	}
		    case OFFSET_P1_DEC:
		    	switch(type)
		    	{
		    		case TwineCipher.TWINE_CIPHER_80:
		    			TwineCipher m_instance = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80);
		    			len_data  = m_instance.process(TwineCipher.OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case TwineCipher.TWINE_CIPHER_128:
		    			TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80); //TODO change that
		    			return;
		    		case LBLOCK_CIPHER:
		    			LBlockCipher m_instance_lblock= LBlockCipher.getInstance();
		    			len_data  = m_instance_lblock.process(OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case ZORRO_CIPHER:
		    			ZorroCipher m_instance_zorro = ZorroCipher.getInstance();
		    			len_data  = m_instance_zorro.process(OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case PICOLLO_CIPHER:
		    			PicolloCipher m_instance_picollo = PicolloCipher.getInstance();
		    			len_data  = m_instance_picollo.process(OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case RECTANGLE_CIPHER:
		    			RectangleCipher m_instance_rectangle = RectangleCipher.getInstance();
		    			len_data  = m_instance_rectangle.process(OFFSET_P1_DEC, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		default:
		    			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		    	}
		    case OFFSET_P1_GEN:
		    	switch(type)
		    	{
		    		case TwineCipher.TWINE_CIPHER_80:
		    			TwineCipher m_instance = TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80);
		    			len_data = m_instance.process(TwineCipher.OFFSET_P1_GEN, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		case TwineCipher.TWINE_CIPHER_128:
		    			TwineCipher.getInstance(TwineCipher.TWINE_CIPHER_80); //TODO change that
		    			return;
		    		case LBLOCK_CIPHER:
		    			LBlockCipher m_instance_lblock= LBlockCipher.getInstance();
		    			len_data  = m_instance_lblock.process(OFFSET_P1_GEN, buf, (short)(ISO7816.OFFSET_CDATA), count_data);
		    			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
		    			return;
		    		default:
		    			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		    	}
		    	default:
		    		break;
		}
	}

	private void processTest(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		byte state = (buf[ISO7816.OFFSET_P1]);
		byte type = (buf[ISO7816.OFFSET_P2]);
		short count_data = (short) (buf[ISO7816.OFFSET_LC] & 0xff);
		if(count_data < 0)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		TestCase m_Instance = TestCase.getInstance();
		switch(state)
		{
			case CMD_TEST_LOOP_INC:
			 	m_Instance.runInc();
				break;
			case CMD_TEST_LOOP_DEC:
			 	m_Instance.runDec();
				break;
			case CMD_TEST_WRITE_RAM_DESELECT:
				m_Instance.testWriteRamRamDeselect();
				break;
			case CMD_TEST_WRITE_RAM_RESET:
				m_Instance.testWriteRamRamReset();
				break;
			case CMD_ADD_BIG:
				m_Instance.testAdditionBig();
				break;
			case CMD_MOD_POW_EEPROM:
				m_Instance.testModPowEeprom();
				break;
			case CMD_MOD_POW_RAM:
				m_Instance.testModPowRam();
				break;
			case CMD_MOD_MULL_EEPROM:
				m_Instance.testModMullEEprom();
				break;
			case CMD_MOD_MULL_RAM:
				m_Instance.testModMullRam();
				break;
			case CMD_TEST_MEMORY:
				m_Instance.testMul();
				break;
				
			default:
					break;
				
		}
	}

	private void processHash(APDU apdu)
	{
		byte[] buf = apdu.getBuffer();
		byte state = (buf[ISO7816.OFFSET_P1]);
		byte type = (buf[ISO7816.OFFSET_P2]);
		byte count_data = buf[ISO7816.OFFSET_LC];
		if(count_data == 0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		short len_data = -1;
		switch(state)
		{
			case IConsts.HASH_KECCAK_160:
			{
				Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_160);
				cipherHash.postInit();
				len_data  = cipherHash.process(HASH, buf, (byte)(ISO7816.OFFSET_CDATA), count_data);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
    			return;
			}
			case IConsts.HASH_KECCAK_r144c256:
			{
				Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r144c256);
				cipherHash.postInit();
				len_data  = cipherHash.process(HASH, buf, (byte)(ISO7816.OFFSET_CDATA), count_data);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
    			return;
			}
			case IConsts.HASH_KECCAK_r128c272:
			{
				Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r128c272);
				cipherHash.postInit();
				len_data  = cipherHash.process(HASH, buf, (byte)(ISO7816.OFFSET_CDATA), count_data);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
    			return;
			}
			case IConsts.HASH_KECCAK_r544c256:
			{
				Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r544c256);
				cipherHash.postInit();
				len_data  = cipherHash.process(HASH, buf, (byte)(ISO7816.OFFSET_CDATA), count_data);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
    			return;
			}
			case IConsts.HASH_KECCAK_r512c288:
			{
				Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r512c288);
				cipherHash.postInit();
				len_data  = cipherHash.process(HASH, buf, (byte)(ISO7816.OFFSET_CDATA), count_data);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
    			return;
			}
			case IConsts.HASH_KECCAK_r256c544:
			{
				Sha3Keccak cipherHash = Sha3Keccak.getInstance(IConsts.HASH_KECCAK_r256c544);
				cipherHash.postInit();
				len_data  = cipherHash.process(HASH, buf, (byte)(ISO7816.OFFSET_CDATA), count_data);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len_data);
    			return;
			}
		}
	}

	
}
