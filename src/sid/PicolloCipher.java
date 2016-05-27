package sid;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class PicolloCipher implements IConsts {
  
	public static final short RN = 100;
	public static final short BLOCK_SIZE=64;
	public static final short GF_POLY = 0x13;
	public static final short KEYSIZE=80;
	public static final short DEG_GF_POLY=4;
	public static final short MEMORY_TEMPORARY=142;
	public static final short BYTE_LENGTH=0x08;
	private boolean decryptMode = false;
	
	/**
	 *  0-16 temporary used 
	 *  short ofset_wkey = 16-23; // for index accesing ehitenin key
		short offset_rkey=24-123; // for temporary rkey
		block_text 124-131
		key 132-141
	 */
	
	/**/
	public  byte[] temp  	 =  JCSystem.makeTransientByteArray(MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT); 
	final byte[] SBox = {
			0xE, 0x4, 0xB, 0x2, 0x3, 0x8, 0x0, 0x9,
			0x1, 0xA, 0x7, 0xF, 0x6, 0xC, 0x5, 0xD
	};
	final byte[] C = {  0x07,0x1c,0x29,0x3d,0x1f ,0x1a,0x25,0x3e, 0x17,0x18,0x21,0x3f, 0x2f,0x16,0x3d,0x38,0x27,0x14,0x39,0x39,
			0x3f,0x12,0x35,0x3a, 0x37,0x10,0x31,0x3b, 0x4f,0x0e,0x0d,0x34, 0x47,0x0c,0x09,0x35, 0x5f,0x0a,0x05,0x36,
			0x57,0x08,0x01,0x37, 0x6f, 0x06,0x1d,0x30, 0x67,0x04,0x19,0x31, 0x7f,0x02,0x15,0x32, 0x77,0x00,0x11,0x33,
			(byte) 0x8f,0x3e,0x6d,0x2c, (byte) 0x87, 0x3c,0x69,0x2d, (byte) 0x9f,0x3a,0x65,0x2e, (byte) 0x97,0x38,0x61,0x2f, (byte) 0xaf,0x36,0x7d,0x28,
			(byte) 0xa7,0x34,0x79,0x29, (byte) 0xbf, 0x32,0x75,0x2a, (byte) 0xb7,0x30,0x71,0x2b, (byte) 0xcf,0x2e,0x4d,0x24, (byte) 0xc7,0x2c,0x49,0x25
		};
	final byte[] M = { 0x2,0x3,0x1,0x1,0x1,0x2,0x3,0x1,0x1,0x1,0x2,0x3 ,0x3,0x1,0x1,0x2 };
	
	static PicolloCipher m_instance=null;
	
	public static PicolloCipher getInstance()
	{
		if(m_instance == null)
		{
			m_instance = new PicolloCipher();
		}
		return m_instance;
	}
	byte gm(byte a, byte b)
	{
		byte g = 0;
		short i;
		for (i = 0; i < DEG_GF_POLY; i++) {
			if ((b & 0x1) == 1) 
			{
				g ^= a;
			}
			byte hbs = (byte) (a & 0x8);
			a <<= 0x1;
			if (hbs == 0x8) { a ^= GF_POLY; }
			b >>= 0x1;
		}
		return g;
	}
	void rp(byte[] s,short offset) 
	{
		Util.arrayCopy(s, offset, temp, (short)0, (byte)8);
		s[(short)(6+offset)] = temp[0];
		s[(short)(3+offset)] = temp[1];
		s[(short)(0+offset)] = temp[2];
		s[(short)(5+offset)] = temp[3];
		s[(short)(2+offset)] = temp[4];
		s[(short)(7+offset)] = temp[5];
		s[(short)(4+offset)] = temp[6];
		s[(short)(1+offset)] = temp[7];
	}
	void f(byte b[],short offset)
	{
		
		temp[0] = SBox[(b[offset] >> 4) & 0xf];
		temp[1] = SBox[(b[offset] >> 0) & 0xf];
		temp[2] = SBox[(b[(short)(offset + 1)] >> 4) & 0xf];
		temp[3] = SBox[(b[(short)(offset+1)] >> 0) & 0xf];

		temp[5] = (byte) (gm(temp[0], M[0]) ^ gm(temp[1], M[1]) ^ gm(temp[2], M[2]) ^ gm(temp[3], M[3]));
		temp[6] = (byte) (gm(temp[0], M[4]) ^ gm(temp[1], M[5]) ^ gm(temp[2], M[6]) ^ gm(temp[3], M[7]));
		temp[7] = (byte) (gm(temp[0], M[8]) ^ gm(temp[1], M[9]) ^ gm(temp[2], M[10]) ^ gm(temp[3], M[11]));
		temp[8] = (byte) (gm(temp[0], M[12])^ gm(temp[1], M[13])^ gm(temp[2], M[14]) ^ gm(temp[3], M[15]));
		
		temp[0] = SBox[temp[5]];
		temp[1] = SBox[temp[6]];
		temp[2] = SBox[temp[7]];
		temp[3] = SBox[temp[8]];

		b[offset] = (byte) ((temp[0] << 4) ^ temp[1]);
		b[(short)(1+offset)] = (byte) ((temp[2] << 4) ^ temp[3]);
	}
	void keySchedule(byte[] x,short offset)
	{
		short ofset_wkey = 16;
		short offset_rkey=24;
		//compute keys 
		short r = 0,i=0; 
		Util.arrayFillNonAtomic(temp,(short) 16,(short) 108, (byte) 0);
		
		for(r = offset;r<(short)(offset + 10);r++)
		{
			x[r] = (byte)((short) (x[r] & 0x00FF));
		}
		
		temp[ofset_wkey] ^= x[offset];
		temp[(short)(ofset_wkey+1)] ^= x[(short)(3 + offset)];
		temp[(short)(ofset_wkey+2)] ^= x[(short)(2 + offset)];
		temp[(short)(ofset_wkey+3)] ^= x[(short)(1 + offset)];
		temp[(short)(ofset_wkey+4)] ^= x[(short)(8 + offset)];
		temp[(short)(ofset_wkey+5)] ^= x[(short)(7 + offset)];
		temp[(short)(ofset_wkey+6)] ^= x[(short)(6 + offset)];
		temp[(short)(ofset_wkey+7)] ^= x[(short)(9 + offset)];

		for (r = 0; r < RN; r+=4)
		{
			temp[(short)(r+offset_rkey)]   ^= C[r];
			temp[(short)(r+1+offset_rkey)] ^= C[(short)(r+1)];
			temp[(short)(r+2+offset_rkey)] ^= C[(short)(r+2)];
			temp[(short)(r+3+offset_rkey)] ^= C[(short)(r+3)];

			if (i % 5 == 0 || i % 5 == 2)
			{
				temp[(short)(r + offset_rkey)]   ^= x[(short)(4 + offset)];
				temp[(short)(r+1+offset_rkey)]   ^= x[(short)(5 + offset)];
				temp[(short)(r+2+offset_rkey)]   ^= x[(short)(6 + offset)];
				temp[(short)(r+3+offset_rkey)]   ^= x[(short)(7 + offset)];
			}
			else if (i % 5 == 1 || i % 5 == 4)
			{
				temp[(short)(r + offset_rkey)]  ^= x[(short)(0 + offset)];
				temp[(short)(r + offset_rkey+1)] ^= x[(short)(1 + offset)];
				temp[(short)(r + offset_rkey+2)] ^= x[(short)(2 + offset)];
				temp[(short)(r + offset_rkey+3)] ^= x[(short)(3 + offset)];
			}
			else if (i % 5 == 3)
			{
				temp[(short)(r + offset_rkey)]   ^= x[(short)(8 + offset)];
				temp[(short)(r + offset_rkey+1)] ^= x[(short)(9 + offset)];
				temp[(short)(r + offset_rkey+2)] ^= x[(short)(8 + offset)];
				temp[(short)(r + offset_rkey+3)] ^= x[(short)(9 + offset)];
			}
			i++;
		}

	}

	
	public void encrypt(byte[] plain,short offset)
	{
		short ofset_wkey = 16;
		short offset_rkey=24;
		short offset_x = 10;
		short r=0;
		//if(decryptMode == false)
		//	keySchedule(key,offset_key);
		plain[(short)(0+offset)] ^= temp[(short)(0+ofset_wkey)];
		plain[(short)(1+offset)] ^= temp[(short)(1+ofset_wkey)];
		plain[(short)(4+offset)] ^= temp[(short)(2+ofset_wkey)];
		plain[(short)(5+offset)] ^= temp[(short)(3+ofset_wkey)];
		
		temp[(short)(0+offset_x)] = 0;
		temp[(short)(1+offset_x)] = 0 ;
		for(r = 0 ; r < RN;r+=4)
		{
			plain[(short)(2+offset)] ^= temp[(short)(r+offset_rkey)];
			plain[(short)(3+offset)] ^= temp[(short)(r+1+offset_rkey)];
			
			temp[(short)(0+offset_x)] = plain[(short)(0+offset)];
			temp[(short)(1+offset_x)] = plain[(short)(1+offset)];
			
			f(temp,offset_x);
			
			plain[(short)(2+offset)] ^= temp[(short)(0+offset_x)];
			plain[(short)(3+offset)] ^= temp[(short)(1+offset_x)];
			
			plain[(short)(6+offset)] ^= temp[(short)(r+2+offset_rkey)];
			plain[(short)(7+offset)] ^= temp[(short)(r+3+offset_rkey)];
			
			temp[(short)(0+offset_x)] = plain[(short)(4+offset)];
			temp[(short)(1+offset_x)] = plain[(short)(5+offset)];
			
			f(temp,offset_x);
			
			plain[(short)(6+offset)] ^= temp[(short)(0+offset_x)];
			plain[(short)(7+offset)] ^= temp[(short)(1+offset_x)];
			
			if(r != ((short)(RN-4)))
				rp(plain,offset);
			
		}
		plain[(short)(0+offset)] ^= temp[(short)(4+ofset_wkey)];
		plain[(short)(1+offset)] ^= temp[(short)(5+ofset_wkey)];
		plain[(short)(4+offset)] ^= temp[(short)(6+ofset_wkey)];
		plain[(short)(5+offset)] ^= temp[(short)(7+ofset_wkey)];
	}
	public void decrypt(byte[] cipher,short offset)
	{
		short ofset_wkey = 16;
		short offset_rkey=24;
	 	short dlenght = BLOCK_SIZE/BYTE_LENGTH;
		short r=0,i=0;
		
		//decryptMode=true;
		//keySchedule(key,offset_key);
		
		Util.arrayCopy(temp, ofset_wkey, temp,OFFSET_START,dlenght);
		temp[(short)(0+ofset_wkey)] = temp[(short)(4)];
		temp[(short)(1+ofset_wkey)] = temp[(short)(5)];
		temp[(short)(2+ofset_wkey)] = temp[(short)(6)];
		temp[(short)(3+ofset_wkey)] = temp[(short)(7)];
		temp[(short)(4+ofset_wkey)] = temp[(short)(0)];
		temp[(short)(5+ofset_wkey)] = temp[(short)(1)];
		temp[(short)(6+ofset_wkey)] = temp[(short)(2)];
		temp[(short)(7+ofset_wkey)] = temp[(short)(3)];
		short end_round = (short)(RN/2 - 4);
		for ( r = 0 ; r < end_round;r+=4)
		{
			if(i%2 == 0)
			{
				temp[(short)(r+0+offset_rkey)] ^= temp[(short)(RN - r - 4+offset_rkey)];
				temp[(short)(RN - r - 4+offset_rkey)] ^= temp[(short)(r+0+offset_rkey)];
				temp[(short)(r+0+offset_rkey)] ^= temp[(short)(RN - r - 4+offset_rkey)];
				
				temp[(short)(r+1+offset_rkey)] ^= temp[(short)(RN - r - 3+offset_rkey)];
				temp[(short)(RN - r - 3+offset_rkey)] ^= temp[(short)(r+1+offset_rkey)];
				temp[(short)(r+1+offset_rkey)] ^= temp[(short)(RN - r - 3+offset_rkey)];
				
				temp[(short)(r+2+offset_rkey)] ^= temp[(short)(RN - r - 2+offset_rkey)];
				temp[(short)(RN - r - 2+offset_rkey)] ^= temp[(short)(r+2+offset_rkey)];
				temp[(short)(r+2+offset_rkey)] ^= temp[(short)(RN - r - 2+offset_rkey)];
				
				temp[(short)(r+3+offset_rkey)] ^= temp[(short)(RN - r - 1+offset_rkey)];
				temp[(short)(RN - r - 1+offset_rkey)] ^= temp[(short)(r+3+offset_rkey)];
				temp[(short)(r+3+offset_rkey)] ^= temp[(short)(RN - r - 1+offset_rkey)];
				
			}
			else
			{
				
				temp[(short)(r+0+offset_rkey)] ^= temp[(short)(RN - r - 2+offset_rkey)];
				temp[(short)(RN - r - 2+offset_rkey)] ^= temp[(short)(r+0+offset_rkey)];
				temp[(short)(r+0+offset_rkey)] ^= temp[(short)(RN - r - 2+offset_rkey)];
				
				temp[(short)(r+1+offset_rkey)] ^= temp[(short)(RN - r - 1+offset_rkey)];
				temp[(short)(RN - r - 1+offset_rkey)] ^= temp[(short)(r+1+offset_rkey)];
				temp[(short)(r+1+offset_rkey)] ^= temp[(short)(RN - r - 1+offset_rkey)];
				
				temp[(short)(r+2+offset_rkey)] ^= temp[(short)(RN - r - 4+offset_rkey)];
				temp[(short)(RN - r - 4+offset_rkey)] ^= temp[(short)(r+2+offset_rkey)];
				temp[(short)(r+2+offset_rkey)] ^= temp[(short)(RN - r - 4+offset_rkey)];
				
				temp[(short)(r+3+offset_rkey)] ^= temp[(short)(RN - r - 3+offset_rkey)];
				temp[(short)(RN - r - 3+offset_rkey)] ^= temp[(short)(r+3+offset_rkey)];
				temp[(short)(r+3+offset_rkey)] ^= temp[(short)(RN - r - 3+offset_rkey)];
				
				
			}
			i++;
		}
		encrypt(cipher, offset);
	}
	
	public void generateKey(byte[] key,short offset_key)
	{
		keySchedule(key,offset_key);
	}
	public short process(byte type,byte[] data,short start_offset,short len_data)
    {
	   	short dlenght = BLOCK_SIZE/BYTE_LENGTH;
	   	short klength = KEYSIZE/BYTE_LENGTH;
    	Util.arrayCopy(data, start_offset, temp, (short)124, dlenght); // block text 124-31
    	Util.arrayCopy(data, (short)(start_offset+8), temp, (short)132,klength);
    	switch(type)
    	{
    		case OFFSET_P1_ENC:
    			encrypt(temp, (short)124);
    			Util.arrayCopy(temp,(short)124, data, (short) start_offset, len_data);
    			return dlenght;
    		case OFFSET_P1_DEC:
    			decrypt(temp,(short)124);
    			Util.arrayCopy(temp,(short)124, data, (short) start_offset, len_data);
    			return dlenght;
    		case OFFSET_P1_GEN:
    			generateKey(temp, (short)132);
    			Util.arrayCopy(temp,(short)132, data, (short) start_offset, len_data);
    			return dlenght;
    		default:
    			return INVALID_DATA_LENGTH;
    	}
    }
}
