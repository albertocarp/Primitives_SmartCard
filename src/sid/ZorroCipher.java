package sid;

import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacardx.crypto.Cipher;

public class ZorroCipher extends Cipher implements IConsts
{
	
	private  final byte [] s = {
		(byte) 0xB2, (byte) 0xE5, 0x5E, (byte) 0xFD, 0x5F, (byte) 0xC5, 0x50, (byte) 0xBC, (byte) 0xDC, 0x4A, (byte) 0xFA, (byte) 0x88, 0x28, (byte) 0xD8, (byte) 0xE0, (byte) 0xD1,
		(byte) 0xB5, (byte) 0xD0, 0x3C, (byte) 0xB0, (byte) 0x99, (byte) 0xC1, (byte) 0xE8, (byte) 0xE2, 0x13, 0x59, (byte) 0xA7, (byte) 0xFB, 0x71, 0x34, 0x31, (byte) 0xF1,
		(byte) 0x9F, 0x3A, (byte) 0xCE, 0x6E, (byte) 0xA8, (byte) 0xA4, (byte) 0xB4, 0x7E, 0x1F, (byte) 0xB7, 0x51, 0x1D, 0x38, (byte) 0x9D, 0x46, 0x69,
		0x53, 0x0E, 0x42, 0x1B, 0x0F, 0x11, 0x68, (byte) 0xCA, (byte) 0xAA, 0x06, (byte) 0xF0, (byte) 0xBD, 0x26, 0x6F, 0x00, (byte) 0xD9,
		0x62, (byte) 0xF3, 0x15, 0x60, (byte) 0xF2, 0x3D, 0x7F, 0x35, 0x63, 0x2D, 0x67, (byte) 0x93, 0x1C, (byte) 0x91, (byte) 0xF9, (byte) 0x9C,
		0x66, 0x2A, (byte) 0x81, 0x20, (byte) 0x95, (byte) 0xF8, (byte) 0xE3, 0x4D, 0x5A, 0x6D, 0x24, 0x7B, (byte) 0xB9, (byte) 0xEF, (byte) 0xDF, (byte) 0xDA,
		0x58, (byte) 0xA9, (byte) 0x92, 0x76, 0x2E, (byte) 0xB3, 0x39, 0x0C, 0x29, (byte) 0xCD, 0x43, (byte) 0xFE, (byte) 0xAB, (byte) 0xF5, (byte) 0x94, 0x23,
		0x16, (byte) 0x80, (byte) 0xC0, 0x12, 0x4C, (byte) 0xE9, 0x48, 0x19, 0x08, (byte) 0xAE, 0x41, 0x70, (byte) 0x84, 0x14, (byte) 0xA2, (byte) 0xD5,
		(byte) 0xB8, 0x33, 0x65, (byte) 0xBA, (byte) 0xED, 0x17, (byte) 0xCF, (byte) 0x96, 0x1E, 0x3B, 0x0B, (byte) 0xC2, (byte) 0xC8, (byte) 0xB6, (byte) 0xBB, (byte) 0x8B,
		(byte) 0xA1, 0x54, 0x75, (byte) 0xC4, 0x10, 0x5D, (byte) 0xD6, 0x25, (byte) 0x97, (byte) 0xE6, (byte) 0xFC, 0x49, (byte) 0xF7, 0x52, 0x18, (byte) 0x86,
		(byte) 0x8D, (byte) 0xCB, (byte) 0xE1, (byte) 0xBF, (byte) 0xD7, (byte) 0x8E, 0x37, (byte) 0xBE, (byte) 0x82, (byte) 0xCC, 0x64, (byte) 0x90, 0x7C, 0x32, (byte) 0x8F, 0x4B,
		(byte) 0xAC, 0x1A, (byte) 0xEA, (byte) 0xD3, (byte) 0xF4, 0x6B, 0x2C, (byte) 0xFF, 0x55, 0x0A, 0x45, 0x09, (byte) 0x89, 0x01, 0x30, 0x2B,
		(byte) 0xD2, 0x77, (byte) 0x87, 0x72, (byte) 0xEB, 0x36, (byte) 0xDE, (byte) 0x9E, (byte) 0x8C, (byte) 0xDB, 0x6C, (byte) 0x9B, 0x05, 0x02, 0x4E, (byte) 0xAF,
		0x04, (byte) 0xAD, 0x74, (byte) 0xC3, (byte) 0xEE, (byte) 0xA6, (byte) 0xF6, (byte) 0xC7, 0x7D, 0x40, (byte) 0xD4, 0x0D, 0x3E, 0x5B, (byte) 0xEC, 0x78,
		(byte) 0xA0, (byte) 0xB1, 0x44, 0x73, 0x47, 0x5C, (byte) 0x98, 0x21, 0x22, 0x61, 0x3F, (byte) 0xC6, 0x7A, 0x56, (byte) 0xDD, (byte) 0xE7,
		(byte) 0x85, (byte) 0xC9, (byte) 0x8A, 0x57, 0x27, 0x07, (byte) 0x9A, 0x03, (byte) 0xA3, (byte) 0x83, (byte) 0xE4, 0x6A, (byte) 0xA5, 0x2F, 0x79, 0x4F
	};
	
	private  final byte [] inv_s = {
			0x3E, (byte) 0xBD, (byte) 0xCD, (byte) 0xF7, (byte) 0xD0, (byte) 0xCC, 0x39, (byte) 0xF5, 0x78, (byte) 0xBB, (byte) 0xB9, (byte) 0x8A, 0x67, (byte) 0xDB, 0x31, 0x34,
			(byte) 0x94, 0x35, 0x73, 0x18, 0x7D, 0x42, 0x70, (byte) 0x85, (byte) 0x9E, 0x77, (byte) 0xB1, 0x33, 0x4C, 0x2B, (byte) 0x88, 0x28,
			0x53, (byte) 0xE7, (byte) 0xE8, 0x6F, 0x5A, (byte) 0x97, 0x3C, (byte) 0xF4, 0x0C, 0x68, 0x51, (byte) 0xBF, (byte) 0xB6, 0x49, 0x64, (byte) 0xFD,
			(byte) 0xBE, 0x1E, (byte) 0xAD, (byte) 0x81, 0x1D, 0x47, (byte) 0xC5, (byte) 0xA6, 0x2C, 0x66, 0x21, (byte) 0x89, 0x12, 0x45, (byte) 0xDC, (byte) 0xEA,
			(byte) 0xD9, 0x7A, 0x32, 0x6A, (byte) 0xE2, (byte) 0xBA, 0x2E, (byte) 0xE4, 0x76, (byte) 0x9B, 0x09, (byte) 0xAF, 0x74, 0x57, (byte) 0xCE, (byte) 0xFF,
			0x06, 0x2A, (byte) 0x9D, 0x30, (byte) 0x91, (byte) 0xB8, (byte) 0xED, (byte) 0xF3, 0x60, 0x19, 0x58, (byte) 0xDD, (byte) 0xE5, (byte) 0x95, 0x02, 0x04,
			0x43, (byte) 0xE9, 0x40, 0x48, (byte) 0xAA, (byte) 0x82, 0x50, 0x4A, 0x36, 0x2F, (byte) 0xFB, (byte) 0xB5, (byte) 0xCA, 0x59, 0x23, 0x3D,
			0x7B, 0x1C, (byte) 0xC3, (byte) 0xE3, (byte) 0xD2, (byte) 0x92, 0x63, (byte) 0xC1, (byte) 0xDF, (byte) 0xFE, (byte) 0xEC, 0x5B, (byte) 0xAC, (byte) 0xD8, 0x27, 0x46,
			0x71, 0x52, (byte) 0xA8, (byte) 0xF9, 0x7C, (byte) 0xF0, (byte) 0x9F, (byte) 0xC2, 0x0B, (byte) 0xBC, (byte) 0xF2, (byte) 0x8F, (byte) 0xC8, (byte) 0xA0, (byte) 0xA5, (byte) 0xAE,
			(byte) 0xAB, 0x4D, 0x62, 0x4B, 0x6E, 0x54, (byte) 0x87, (byte) 0x98, (byte) 0xE6, 0x14, (byte) 0xF6, (byte) 0xCB, 0x4F, 0x2D, (byte) 0xC7, 0x20,
			(byte) 0xE0, (byte) 0x90, 0x7E, (byte) 0xF8, 0x25, (byte) 0xFC, (byte) 0xD5, 0x1A, 0x24, 0x61, 0x38, 0x6C, (byte) 0xB0, (byte) 0xD1, 0x79, (byte) 0xCF,
			0x13, (byte) 0xE1, 0x00, 0x65, 0x26, 0x10, (byte) 0x8D, 0x29, (byte) 0x80, 0x5C, (byte) 0x83, (byte) 0x8E, 0x07, 0x3B, (byte) 0xA7, (byte) 0xA3,
			0x72, 0x15, (byte) 0x8B, (byte) 0xD3, (byte) 0x93, 0x05, (byte) 0xEB, (byte) 0xD7, (byte) 0x8C, (byte) 0xF1, 0x37, (byte) 0xA1, (byte) 0xA9, 0x69, 0x22, (byte) 0x86,
			0x11, 0x0F, (byte) 0xC0, (byte) 0xB3, (byte) 0xDA, 0x7F, (byte) 0x96, (byte) 0xA4, 0x0D, 0x3F, 0x5F, (byte) 0xC9, 0x08, (byte) 0xEE, (byte) 0xC6, 0x5E,
			0x0E, (byte) 0xA2, 0x17, 0x56, (byte) 0xFA, 0x01, (byte) 0x99, (byte) 0xEF, 0x16, 0x75, (byte) 0xB2, (byte) 0xC4, (byte) 0xDE, (byte) 0x84, (byte) 0xD4, 0x5D,
			0x3A, 0x1F, 0x44, 0x41, (byte) 0xB4, 0x6D, (byte) 0xD6, (byte) 0x9C, 0x55, 0x4E, 0x0A, 0x1B, (byte) 0x9A, 0x03, 0x6B, (byte) 0xB7
		};
	
	public static final short MAX_MEMORY_TEMPORARY=40;
	
	private static ZorroCipher m_instance = null;
	
	 // use 24 - 32 as temp copy
	public  byte[] temp   =  JCSystem.makeTransientByteArray(MAX_MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT);
	
	byte mulGaloisField2_8(byte a,byte b)
	{
		byte p = 0;
		byte bit_set;
		byte counter=0;
		
		for(counter = 0 ; counter < 8 ; counter++)
		{
			if ((b & 1) == 1)
				p ^= a;
			bit_set = (byte) (a & 0x80);
			a <<= 1;
			if (bit_set == (byte)(0x80))
				a ^= 0x1b;
			b >>= 1;
		}
		return p;
	}
	
	void mixColumn(byte[] column,short offset)
	{
		byte i;
		byte offset_cpy = 36;
		for (i = 0; i < 4; i++) {
			temp[(short)(i + offset_cpy)] = column[(short)(i+offset)];
		}
		column[(short)(0+offset)] = (byte) (mulGaloisField2_8(temp[offset_cpy],(byte)2) ^
			mulGaloisField2_8(temp[(short)(1+ offset_cpy)], (byte) 3) ^
			mulGaloisField2_8(temp[(short)(2+ offset_cpy)], (byte) 1) ^
			mulGaloisField2_8(temp[(short)(3+ offset_cpy)], (byte) 1));
		column[(short)(1+offset)] = (byte) (mulGaloisField2_8(temp[0+ offset_cpy], (byte) 1) ^
			mulGaloisField2_8(temp[(short)(1+ offset_cpy)], (byte) 2) ^
			mulGaloisField2_8(temp[(short)(2+ offset_cpy)], (byte) 3) ^
			mulGaloisField2_8(temp[(short)(3+ offset_cpy)], (byte) 1));
		column[(short)(2+offset)] = (byte) (mulGaloisField2_8(temp[0+ offset_cpy], (byte) 1) ^
			mulGaloisField2_8(temp[(short)(1+ offset_cpy)], (byte) 1) ^
			mulGaloisField2_8(temp[(short)(2+ offset_cpy)], (byte) 2) ^
			mulGaloisField2_8(temp[(short)(3+ offset_cpy)], (byte) 3));
		column[(short)(3+offset)] = (byte) (mulGaloisField2_8(temp[offset_cpy], (byte) 3) ^
			mulGaloisField2_8(temp[(short)(1+ offset_cpy)], (byte) 1) ^
			mulGaloisField2_8(temp[(short)(2+ offset_cpy)], (byte) 1) ^
			mulGaloisField2_8(temp[(short)(3+ offset_cpy)], (byte) 2));
	}
	void invMixColumn(byte[] column,short offset) {
		byte i;
		byte offset_cpy = 36;
		for (i = 0; i < 4; i++) {
			temp[i + offset_cpy] = column[(short)(i + offset)];
		}
		column[(short)(0 + offset)] = (byte) (mulGaloisField2_8(temp[offset_cpy], (byte) 14) ^
			mulGaloisField2_8(temp[(short)(1+offset_cpy)], (byte) 11) ^
			mulGaloisField2_8(temp[(short)(2+offset_cpy)], (byte) 13) ^
			mulGaloisField2_8(temp[(short)(3+offset_cpy)], (byte) 9));
		column[(short)(1 + offset)] = (byte) (mulGaloisField2_8(temp[offset_cpy], (byte) 9) ^
			mulGaloisField2_8(temp[(short)(1+offset_cpy)], (byte) 14) ^
			mulGaloisField2_8(temp[(short)(2+offset_cpy)], (byte) 11) ^
			mulGaloisField2_8(temp[(short)(3+offset_cpy)], (byte) 13));
		column[(short)(2+offset)] = (byte) (mulGaloisField2_8(temp[offset_cpy], (byte) 13) ^
			mulGaloisField2_8(temp[(short)(1+offset_cpy)], (byte) 9) ^
			mulGaloisField2_8(temp[(short)(2+offset_cpy)], (byte) 14) ^
			mulGaloisField2_8(temp[(short)(3+offset_cpy)], (byte) 11));
		column[(short)(3+offset)] = (byte) (mulGaloisField2_8(temp[offset_cpy], (byte) 11) ^
			mulGaloisField2_8(temp[(short)(1+offset_cpy)], (byte) 13) ^
			mulGaloisField2_8(temp[(short)(2+offset_cpy)], (byte) 9) ^
			mulGaloisField2_8(temp[(short)(3+offset_cpy)], (byte) 14));
	}
   
	void zorro_InvMixColumns(byte[] internBuffer,short offset) {
		short i, j;
		byte offset_cpy = 32;
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 4; j++) {
				temp[(short)(offset_cpy + j)] = internBuffer[(short)((i * 4) + j)];
			}
			invMixColumn(temp,offset_cpy);
			for (j = 0; j < 4; j++) {
				internBuffer[(short)((i * 4) + j)] = temp[(short)(j + offset_cpy)];
			}
		}
	}
	
	void zorro_MixColumns(byte[] internBuffer,short offset) {
		short  i, j;
		byte offset_cpy = 32;
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 4; j++) {
				temp[(short)(j + offset_cpy)] = internBuffer[(short)((i * 4) + j + offset)];
			}
			mixColumn(temp,offset_cpy);
			for (j = 0; j < 4; j++) {
				internBuffer[(short)((i * 4) + j + offset)] = temp[(short)(j + offset_cpy)];
			}
	}
}
	 
	void zorroOneRoundEnc(byte[] state,short offset_state,byte round)
	{
		state[(short)(0 + offset_state)] = s[(short)(state[(short)(0+ offset_state)] & 0x00ff)];
		state[(short)(4+ offset_state)] = s[(short)(state[(short)(4+ offset_state)] & 0x00ff)];
		state[(short)(8+ offset_state)] = s[(short)(state[(short)(8+ offset_state)] & 0x00ff)];
		state[(short)(12+ offset_state)] =s[(short)(state[(short)(12+ offset_state)] & 0x00ff)];
		
		state[(short)(0 + offset_state)] = (byte) (state[(short)(0+ offset_state)] ^ round);
		state[(short)(4+ offset_state)] = (byte) (state[(short)(4+ offset_state)] ^ round);
		state[(short)(8+ offset_state)] = (byte) (state[(short)(8+ offset_state)] ^ round);
		state[(short)(12+ offset_state)] = (byte) (state[(short)(12+offset_state)] ^ (round << 3));
		
		/*shiift the rows*/
		byte tmp = (byte) (state[(short)(1+offset_state)] );
		state[(short)(1+offset_state)] = (byte) (state[(short)(5+offset_state)] & 0x00ff);
		state[(short)(5+offset_state)] = state[(short)(9+offset_state)];
		state[(short)(9+offset_state)] = state[(short)(13+offset_state)];
		state[(short)(13+offset_state)] = tmp;

		tmp = state[(short)(2+offset_state)];
		state[(short)(2+offset_state)] = state[(short)(10+offset_state)];
		state[(short)(10+offset_state)] = tmp;
		
		tmp = state[(short)(6+offset_state)];
		state[(short)(6+offset_state)] = state[(short)(14+offset_state)];
		state[(short)(14+offset_state)] = tmp;

		tmp = state[(short)(3+offset_state)];
		state[(short)(3+offset_state)] = state[(short)(15+offset_state)];
		state[(short)(15+offset_state)] = state[(short)(11+offset_state)];
		state[(short)(11+offset_state)] = state[(short)(7+offset_state)];
		state[(short)(7+offset_state)] = tmp;
		
		zorro_MixColumns(state,offset_state);	
	}
	
	void zorroOneRoundDec(byte[] state,short offset_state,byte round) {
		
		zorro_InvMixColumns(state,offset_state);

		byte tmp = state[(short)(13+offset_state)];
		state[(short)(13+offset_state)] = state[(short)(9+offset_state)];
		state[(short)(9+offset_state)] = state[(short)(5+offset_state)];
		state[(short)(5+offset_state)] = state[(short)(1+offset_state)];
		state[(short)(1+offset_state)] = tmp;

		tmp = state[(short)(2+offset_state)];
		state[(short)(2+offset_state)] = state[(short)(10+offset_state)];
		state[(short)(10+offset_state)] = tmp;
		tmp = state[(short)(6+offset_state)];
		state[(short)(6+offset_state)] = state[(short)(14+offset_state)];
		state[(short)(14+offset_state)] = tmp;

		tmp = state[(short)(3+offset_state)];
		state[(short)(3+offset_state)] = state[(short)(7+offset_state)];
		state[(short)(7+offset_state)] = state[(short)(11+offset_state)];
		state[(short)(11+offset_state)] = state[(short)(15+offset_state)];
		state[(short)(15+offset_state)] = tmp;

		/* Inverse Add Constant */
		state[0] = (byte) (state[(short)(0+offset_state)] ^ round);
		state[4] = (byte) (state[(short)(4+offset_state)] ^ round);
		state[8] = (byte) (state[(short)(8+offset_state)] ^ round);
		state[12] = (byte) (state[(short)(12+offset_state)] ^ (round << 3));


		/* Inverse SubBytes */
		state[(short)(0+offset_state)] = inv_s[(short)(state[(short)(0+ offset_state)] & 0x00ff)];
		state[(short)(4+offset_state)] =  inv_s[(short)(state[(short)(4+ offset_state)] & 0x00ff)];
		state[(short)(8+offset_state)] =  inv_s[(short)(state[(short)(8+ offset_state)] & 0x00ff)];
		state[(short)(12+offset_state)] =  inv_s[(short)(state[(short)(12 + offset_state)] & 0x00ff)];

	};

	void zorroFourRoundEnc(byte[] state,short state_offset,
			byte[]  key,short key_offset, byte round)
	{
		short i = 0;
		zorroOneRoundEnc(state, state_offset, round);
		round++;
		zorroOneRoundEnc(state, state_offset, round);
		round++;
		zorroOneRoundEnc(state, state_offset, round);
		round++;
		zorroOneRoundEnc(state, state_offset, round);
		round++;
		
		for (i=0;i<16;i++)
		{
			state[(short)(i + state_offset)] ^= key[(short)(i + key_offset)];
		}
	}
	
	void zorroFourRoundDec(byte[] state,short state_offset,
			byte[]  key,short key_offset, byte round)
	{
		short i = 0;
		zorroOneRoundDec(state, state_offset, round);
		round--;
		zorroOneRoundDec(state, state_offset, round);
		round--;
		zorroOneRoundDec(state, state_offset, round);
		round--;
		zorroOneRoundDec(state, state_offset, round);
		round--;
		for (i=0;i<16;i++)
		{
			state[(short)(i + state_offset)] ^= key[(short)(i + key_offset)];
		}
	}

	void zorroCompleteEnc(byte[] state,short state_offset,
			byte[]  key,short key_offset)
	{
	   short i=0; 
	   byte round=1;
	   for (i = 0; i < 16; i++) {
			state[(short)(i + state_offset)] ^= key[(short)(i + key_offset)];
	  }
	   zorroFourRoundEnc(state,state_offset,key,key_offset,round);
	   round+=4;
	   zorroFourRoundEnc(state,state_offset,key,key_offset,round);
	   round+=4;
	   zorroFourRoundEnc(state,state_offset,key,key_offset,round);
	   round+=4;
	   zorroFourRoundEnc(state,state_offset,key,key_offset,round);
	   round+=4;
	   zorroFourRoundEnc(state,state_offset,key,key_offset,round);
	   round+=4;
	   zorroFourRoundEnc(state,state_offset,key,key_offset,round);
	 
	}
	
	void zorroCompleteDec(byte[] state,short state_offset,
			byte[]  key,short key_offset)
	{
	   short i=0; 
	   byte round=24;
	   for (i = 0; i < 16; i++) {
			state[(short)(i + state_offset)] ^= key[(short)(i + key_offset)];
	  }
	   zorroFourRoundDec(state,state_offset,key,key_offset,round);
	   round -=4;
	   zorroFourRoundDec(state,state_offset,key,key_offset,round);
	   round -=4;
	   zorroFourRoundDec(state,state_offset,key,key_offset,round);
	   round -=4;
	   zorroFourRoundDec(state,state_offset,key,key_offset,round);
	   round -=4;
	   zorroFourRoundDec(state,state_offset,key,key_offset,round);
	   round-=4;
	   zorroFourRoundDec(state,state_offset,key,key_offset,(byte)4);
	}
	
	public static ZorroCipher getInstance()
	{
		if(m_instance == null)
			m_instance = new ZorroCipher();
		return m_instance;
	}
	public short process(byte type,byte[] data,short start_offset,short len_data)
	 {
		 Util.arrayCopy(data, start_offset, temp, (short) 0, (short) 16);
		 Util.arrayCopy(data, (short) (start_offset+16), temp, (short) 16, (short) 16);
		 
		 switch(type)
	    	{
	    		case OFFSET_P1_ENC:
	    			zorroCompleteEnc(temp,(short)0,temp,(short) 16);
	    			Util.arrayCopy(temp, (short)0, data, (short)(ISO7816.OFFSET_CDATA), (short)16);
	    			return (short)16;
	    		case OFFSET_P1_DEC:
	    			zorroCompleteDec(temp,(short)0,temp,(short) 16);
	    			Util.arrayCopy(temp, (short)0, data, (short)(ISO7816.OFFSET_CDATA), (short)16);
	    			return (short)16;
	    		default:
	    			return (short)-1;
	    	}
	 }

	public short doFinal(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws CryptoException {
		// TODO Auto-generated method stub
		return 0;
	}

	public byte getAlgorithm() {
		// TODO Auto-generated method stub
		return 0;
	}

	public void init(Key arg0, byte arg1) throws CryptoException {
		// TODO Auto-generated method stub
		
	}

	public void init(Key arg0, byte arg1, byte[] arg2, short arg3, short arg4) throws CryptoException {
		// TODO Auto-generated method stub
		
	}

	public short update(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws CryptoException {
		// TODO Auto-generated method stub
		return 0;
	}
}
