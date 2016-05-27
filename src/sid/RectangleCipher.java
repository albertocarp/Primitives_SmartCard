package sid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class RectangleCipher implements IConsts 
{
	public static final short BLOCK_SIZE  = 8;
	public static final short KEY_SIZE= 10;
	public static final short ROUND_KEYS_SIZE= 208;
	public static final short NUMBER_OF_ROUNDS =25;
	public static final short MEMORY_TEMPORARY = 250;
	
	public  byte[] temp  	 =  JCSystem.makeTransientByteArray(MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT); 
	public  short[] tempShort =  JCSystem.makeTransientShortArray((short) 5, JCSystem.CLEAR_ON_DESELECT); //for easy convert
	
	private static RectangleCipher m_Instance=null;
	final byte RC[] = {
			0x01, 0x02, 0x04, 0x09, 0x12, 0x05, 0x0b, 0x16,
			0x0c, 0x19, 0x13, 0x07, 0x0f, 0x1f, 0x1e, 0x1c,
			0x18, 0x11, 0x03, 0x06, 0x0d, 0x1b, 0x17, 0x0e, 0x1d
	};

	void keySchedule(byte[] masterKey,short offsetKey,byte[] roundKey,short offsetRound)
	{
		short i=0;
		short offset_master_key = 22; // 0-9 key 22-31  and 9-17 block
		short offset_temp=18;
		Util.arrayFillNonAtomic(roundKey,offsetRound, (short)200,(byte)0x00);
		/**
		 * Make a copy to the masterKey
		 */
		//stores master key from 0-9
		//stores values from 10-17
		//all the rest are temporary
		for ( i = 0 ; i < KEY_SIZE;i++)
			temp[(short)(offset_master_key+i)] = (byte)(masterKey[(short)(offsetKey + i)] & 0x00FF) ;		
		byte sbox0, sbox1;
		byte tempk0,tempk1;
		roundKey[(short)(offsetRound)] 	 = temp[(short)(offset_master_key+0)];
		roundKey[(short)(1+offsetRound)] = temp[(short)(offset_master_key+1)];
		roundKey[(short)(2+offsetRound)] = temp[(short)(offset_master_key+2)];
		roundKey[(short)(3+offsetRound)] = temp[(short)(offset_master_key+3)];
		roundKey[(short)(4+offsetRound)] = temp[(short)(offset_master_key+4)];
		roundKey[(short)(5+offsetRound)] = temp[(short)(offset_master_key+5)];
		roundKey[(short)(6+offsetRound)] = temp[(short)(offset_master_key+6)];
		roundKey[(short)(7+offsetRound)] = temp[(short)(offset_master_key+7)];
		for (i = 1; i <= NUMBER_OF_ROUNDS; i++)
		{
			temp[(short)(offset_temp)]   = temp[(short)(offset_master_key+0)];
			temp[(short)(offset_temp+1)] = temp[(short)(offset_master_key+2)];
			temp[(short)(offset_temp+2)] = temp[(short)(offset_master_key+4)];
			temp[(short)(offset_temp+3)] = temp[(short)(offset_master_key+6)];
			
			/**
			 * S BOX Layer
			 */
			
			sbox0 = temp[(short)(offset_master_key+4)];
			temp[(short)(offset_master_key+4)] ^= temp[(short)(offset_master_key+2)];
			temp[(short)(offset_master_key+2)] = (byte) ~temp[(short)(offset_master_key+2)];
			sbox1 = temp[(short)(offset_master_key+0)];
			temp[(short)(offset_master_key+0)] &= temp[(short)(offset_master_key+2)];	
			temp[(short)(offset_master_key+2)] |= temp[(short)(offset_master_key+6)];	
			temp[(short)(offset_master_key+2)] ^= sbox1;
			temp[(short)(offset_master_key+6)] ^= sbox0;
			
			
			temp[(short)(offset_master_key+0)] ^= temp[(short)(offset_master_key+6)];
			temp[(short)(offset_master_key+6)] &= temp[(short)(offset_master_key+2)];
			temp[(short)(offset_master_key+6)] ^= temp[(short)(offset_master_key+4)];
			temp[(short)(offset_master_key+4)] |= temp[(short)(offset_master_key+0)];
			temp[(short)(offset_master_key+4)] ^= temp[(short)(offset_master_key+2)];
			temp[(short)(offset_master_key+2)] ^= sbox0;
			
			
			temp[(short)(offset_master_key+0)] = 
					(byte) ((temp[(short)(offset_master_key+0)] & 0x0f) ^ (temp[(short)(offset_temp+0)] & 0xf0));
			temp[(short)(offset_master_key+2)] = 
					(byte) ((temp[(short)(offset_master_key+2)]& 0x0f) ^ (temp[(short)(offset_temp+1)] & 0xf0));
			temp[(short)(offset_master_key+4)] = 
					(byte) ((temp[(short)(offset_master_key+4)] & 0x0f) ^ (temp[(short)(offset_temp+2)] & 0xf0));
			temp[(short)(offset_master_key+6)] =
					(byte) ((temp[(short)(offset_master_key+6)] & 0x0f) ^ (temp[(short)(offset_temp+3)] & 0xf0));
			
			//Aplying Fiestel Generalized transformation
			
			
			// swap the rows
		//	byteToShort(temp,(short)10,(byte)offset_master_key,tempShort);	
			
			//shift the columns
			
			
			tempk0 = temp[offset_master_key];
			tempk1 = temp[(short)(offset_master_key+1)];
			
			temp[(short)(offset_master_key)]= temp[(short)(offset_master_key + 2)];
			temp[(short)(offset_master_key + 1)]= temp[(short)(offset_master_key + 3)];
			
			temp[(short)(offset_master_key+2)]= temp[(short)(offset_master_key + 4)];
			temp[(short)(offset_master_key + 3)]= temp[(short)(offset_master_key + 5)];
			
			temp[(short)(offset_master_key+4)]= temp[(short)(offset_master_key + 6)];
			temp[(short)(offset_master_key + 5)]= temp[(short)(offset_master_key + 7)];
			
			temp[(short)(offset_master_key+6)]= temp[(short)(offset_master_key + 8)];
			temp[(short)(offset_master_key + 7)]= temp[(short)(offset_master_key + 9)];
			
			temp[(short)(offset_master_key+8)]= tempk0;
			temp[(short)(offset_master_key+9)]= tempk1;
			
			temp[(short)(offset_master_key)] ^= tempk1;
			temp[(short)(offset_master_key+1)] ^= tempk0;
			
			tempk0 = temp[(short)(offset_master_key+4)];
			tempk1 = temp[(short)(offset_master_key+5)];
			
			
			short s = Util.makeShort((byte)(tempk1), (byte)(tempk0));
			byte test = (byte) (((s << 12 | s >>>4)));
			temp[(short)(offset_master_key+6)] ^= test ;
			short s3 = (short) ((short)(s >>> 4) & (short)0x0fff | (s << 12));
			short test2 =  (short) ((short)(s3 >>> 8) & (short)(0x00ff));
			temp[(short)(offset_master_key+7)] ^= (byte)test2 ;
			
			
			
			
		//	shortToByte(tempShort,(short)5,temp,offset_master_key);
			temp[(short)(offset_master_key+0)] ^= RC[(short)(i-1)];
			
			
			roundKey[(short)(8*i+offsetRound)] 	 = temp[(short)(offset_master_key+0)];
			roundKey[(short)(8*i+1+offsetRound)] = temp[(short)(offset_master_key+1)];
			
			roundKey[(short)(8*i+2+offsetRound)] = temp[(short)(offset_master_key+2)];
			roundKey[(short)(8*i+3+offsetRound)] = temp[(short)(offset_master_key+3)];
			
			
			roundKey[(short)(8*i+4+offsetRound)] = temp[(short)(offset_master_key+4)];
			roundKey[(short)(8*i+5+offsetRound)] = temp[(short)(offset_master_key+5)];
			
			
			roundKey[(short)(8*i+6+offsetRound)] = temp[(short)(offset_master_key+6)];
			roundKey[(short)(8*i+7+offsetRound)] = temp[(short)(offset_master_key+7)];
			
		}
	}
	
	void encrypt(byte[] plaintext,short offset,byte[] roundKeys,short roundOffset)
	{
		short offset_round_ky=32;
	//	Util.arrayFillNonAtomic(roundKeys, (short)32, (short)8, (byte)0xff);
		keySchedule(roundKeys,roundOffset,temp,(short)offset_round_ky);
		short i=0,r=0;
		byte sbox1,sbox2,sbox3,sbox4;
		for (i = 0; i < NUMBER_OF_ROUNDS; i++)
		{
			plaintext[(short)(0+offset)] ^= roundKeys[(short)(0+r+offset_round_ky)];
			plaintext[(short)(1+offset)] ^= roundKeys[(short)(1+r+offset_round_ky)];
			plaintext[(short)(2+offset)] ^= roundKeys[(short)(2+r+offset_round_ky)];
			plaintext[(short)(3+offset)] ^= roundKeys[(short)(3+r+offset_round_ky)];
			plaintext[(short)(4+offset)] ^= roundKeys[(short)(4+r+offset_round_ky)];
			plaintext[(short)(5+offset)] ^= roundKeys[(short)(5+r+offset_round_ky)];
			plaintext[(short)(6+offset)] ^= roundKeys[(short)(6+r+offset_round_ky)];
			plaintext[(short)(7+offset)] ^= roundKeys[(short)(7+r+offset_round_ky)];
			r+=8;
			
			sbox1 = plaintext[(short)(4+offset)];
			sbox2 = plaintext[(short)(5+offset)];
			
			plaintext[(short)(4+offset)] ^= plaintext[(short)(2+offset)];
			plaintext[(short)(5+offset)] ^= plaintext[(short)(3+offset)];
			
			 plaintext[(short)(2+offset)] = (byte) ~plaintext[(short)(2+offset)];
			 plaintext[(short)(3+offset)] = (byte) ~plaintext[(short)(3+offset)];
			 
			 sbox3 = plaintext[(short)(0+offset)];
			 sbox4 = plaintext[(short)(1+offset)];
			
			 plaintext[(short)(0+offset)] &= plaintext[(short)(2+offset)];
			 plaintext[(short)(1+offset)] &= plaintext[(short)(3+offset)];
			 
			 plaintext[(short)(2+offset)] |= plaintext[(short)(6+offset)];
			 plaintext[(short)(3+offset)] |= plaintext[(short)(7+offset)];
			 
			 plaintext[(short)(2+offset)] ^= sbox3;
			 plaintext[(short)(3+offset)] ^= sbox4;
			 
			 plaintext[(short)(6+offset)] ^= sbox1;
			 plaintext[(short)(7+offset)] ^= sbox2;
			 
			 plaintext[(short)(0+offset)] ^= plaintext[(short)(6+offset)];
			 plaintext[(short)(1+offset)] ^= plaintext[(short)(7+offset)];
			 
			 plaintext[(short)(6+offset)] &= plaintext[(short)(2+offset)];
			 plaintext[(short)(7+offset)] &= plaintext[(short)(3+offset)];
			 
			 plaintext[(short)(6+offset)] ^= plaintext[(short)(4+offset)];
			 plaintext[(short)(7+offset)] ^= plaintext[(short)(5+offset)];
			 
			 plaintext[(short)(4+offset)] |= plaintext[(short)(0+offset)];
			 plaintext[(short)(5+offset)] |= plaintext[(short)(1+offset)];
			 
			 plaintext[(short)(4+offset)] ^= plaintext[(short)(2+offset)];
			 plaintext[(short)(5+offset)] ^= plaintext[(short)(3+offset)];
			 
			 plaintext[(short)(2+offset)] ^= sbox1;
			 plaintext[(short)(3+offset)] ^= sbox2;
			 
			 /**
			  * Now shift the rows
			  */
			 
			 short w1 = Util.makeShort(plaintext[(short)(2+offset)],plaintext[(short)(3+offset)]);
			 w1 = (short) (w1 << 1 | ((short)(w1 >>> 15) & 0x0001));
			 Util.setShort(plaintext,(short) (2+offset), w1);
			 
			 short w2 = Util.makeShort(plaintext[(short)(4+offset)],plaintext[(short)(5+offset)]);
			 w2 = (short) (w2 << 12 | ((short)(w2 >>> 4) & 0x0fff));
			 Util.setShort(plaintext,(short)(4+offset), w2);
			 
			 short w3 = Util.makeShort(plaintext[(short)(6+offset)],plaintext[(short)(7+offset)]);
			 w3 = (short) (w3 << 13 | ((short)(w3 >>> 3) & 0x1fff));
			 Util.setShort(plaintext,(short)(6+offset), w3);
		}
		plaintext[(short)(0+offset)] ^= roundKeys[(short)(0+r+offset_round_ky)];
		plaintext[(short)(1+offset)] ^= roundKeys[(short)(1+r+offset_round_ky)];
		plaintext[(short)(2+offset)] ^= roundKeys[(short)(2+r+offset_round_ky)];
		plaintext[(short)(3+offset)] ^= roundKeys[(short)(3+r+offset_round_ky)];
		plaintext[(short)(4+offset)] ^= roundKeys[(short)(4+r+offset_round_ky)];
		plaintext[(short)(5+offset)] ^= roundKeys[(short)(5+r+offset_round_ky)];
		plaintext[(short)(6+offset)] ^= roundKeys[(short)(6+r+offset_round_ky)];
		plaintext[(short)(7+offset)] ^= roundKeys[(short)(7+r+offset_round_ky)];
	}
	
	void decrypt(byte[] plaintext,short offset,byte[] roundKeys,short roundOffset)
	{
		short offset_round_ky=32;
		//	Util.arrayFillNonAtomic(roundKeys, (short)32, (short)8, (byte)0xff);
			keySchedule(roundKeys,roundOffset,temp,(short)offset_round_ky);
			offset_round_ky = 32+200;
			short i=0,r=0;
			byte sbox1,sbox2,sbox3,sbox4;
			for (i = 0; i < NUMBER_OF_ROUNDS; i++)
			{
				plaintext[(short)(0+offset)] ^= roundKeys[(short)(0+r+offset_round_ky)];
				plaintext[(short)(1+offset)] ^= roundKeys[(short)(1+r+offset_round_ky)];
				plaintext[(short)(2+offset)] ^= roundKeys[(short)(2+r+offset_round_ky)];
				plaintext[(short)(3+offset)] ^= roundKeys[(short)(3+r+offset_round_ky)];
				plaintext[(short)(4+offset)] ^= roundKeys[(short)(4+r+offset_round_ky)];
				plaintext[(short)(5+offset)] ^= roundKeys[(short)(5+r+offset_round_ky)];
				plaintext[(short)(6+offset)] ^= roundKeys[(short)(6+r+offset_round_ky)];
				plaintext[(short)(7+offset)] ^= roundKeys[(short)(7+r+offset_round_ky)];
				r-=8;
				
				// shift rows
				short w1 = Util.makeShort(plaintext[(short)(2+offset)],plaintext[(short)(3+offset)]);
				 w1 = (short) (w1 << 15 | ((short)(w1 >>> 1) & 0x7fff));
				 Util.setShort(plaintext,(short) (2+offset), w1);
				 
				 short w2 = Util.makeShort(plaintext[(short)(4+offset)],plaintext[(short)(5+offset)]);
				 w2 = (short) (w2 << 4 | ((short)(w2 >>> 12) & 0x000f));
				 Util.setShort(plaintext,(short)(4+offset), w2);
				 
				 short w3 = Util.makeShort(plaintext[(short)(6+offset)],plaintext[(short)(7+offset)]);
				 w3 = (short) (w3 << 3 | ((short)(w3 >>> 13) & 0x0007));
				 Util.setShort(plaintext,(short)(6+offset), w3);
				 
				 
				 // invert columns
				sbox1 = plaintext[(short)(0+offset)];
				sbox2 = plaintext[(short)(1+offset)];
				plaintext[(short)(0+offset)] &= plaintext[(short)(4+offset)];
				plaintext[(short)(1+offset)] &= plaintext[(short)(5+offset)];
				
				
				plaintext[(short)(0+offset)] ^= plaintext[(short)(6+offset)];
				plaintext[(short)(1+offset)] ^= plaintext[(short)(7+offset)];
				plaintext[(short)(6+offset)] |= sbox1;
				plaintext[(short)(7+offset)] |= sbox2;
				 
				
				plaintext[(short)(6+offset)] ^= plaintext[(short)(4+offset)];
				plaintext[(short)(7+offset)] ^= plaintext[(short)(5+offset)];	
				plaintext[(short)(2+offset)] ^= plaintext[(short)(6+offset)];
				plaintext[(short)(3+offset)] ^= plaintext[(short)(7+offset)];
				
					
								
				plaintext[(short)(4+offset)] =  plaintext[(short)(2+offset)];;
				plaintext[(short)(5+offset)] =  plaintext[(short)(3+offset)];; 
				plaintext[(short)(2+offset)] ^= sbox1;
				plaintext[(short)(3+offset)] ^= sbox2;
				 
				
				
				plaintext[(short)(2+offset)] ^= plaintext[(short)(0+offset)];
				plaintext[(short)(3+offset)] ^= plaintext[(short)(1+offset)];
				plaintext[(short)(6+offset)] = (byte) ~plaintext[(short)(6+offset)];
				plaintext[(short)(7+offset)] = (byte) ~plaintext[(short)(7+offset)];
				
				
				sbox1 = plaintext[(short)(6+offset)];
				sbox2 = plaintext[(short)(7+offset)];
				
				
				plaintext[(short)(6+offset)] |= plaintext[(short)(2+offset)];
				plaintext[(short)(7+offset)] |= plaintext[(short)(3+offset)];	 
				plaintext[(short)(6+offset)] ^= plaintext[(short)(0+offset)];
				plaintext[(short)(7+offset)] ^= plaintext[(short)(1+offset)];
				 
				
				 plaintext[(short)(0+offset)] &= plaintext[(short)(2+offset)];
				 plaintext[(short)(1+offset)] &= plaintext[(short)(3+offset)];
				 plaintext[(short)(0+offset)] ^= sbox1;
				 plaintext[(short)(1+offset)] ^= sbox2; 
			}
			plaintext[(short)(0+offset)] ^= roundKeys[(short)(0+r+offset_round_ky)];
			plaintext[(short)(1+offset)] ^= roundKeys[(short)(1+r+offset_round_ky)];
			plaintext[(short)(2+offset)] ^= roundKeys[(short)(2+r+offset_round_ky)];
			plaintext[(short)(3+offset)] ^= roundKeys[(short)(3+r+offset_round_ky)];
			plaintext[(short)(4+offset)] ^= roundKeys[(short)(4+r+offset_round_ky)];
			plaintext[(short)(5+offset)] ^= roundKeys[(short)(5+r+offset_round_ky)];
			plaintext[(short)(6+offset)] ^= roundKeys[(short)(6+r+offset_round_ky)];
			plaintext[(short)(7+offset)] ^= roundKeys[(short)(7+r+offset_round_ky)];
	}

	public static RectangleCipher getInstance()
	{
		if(m_Instance == null)
			m_Instance = new RectangleCipher();
		return m_Instance;
	}
	
	public short process(byte type,byte[] data,short start_offset,short len_data)
    {
		short offset_master_key = 0;
		short offset_block=10;
		
    	Util.arrayCopy(data, start_offset, temp, (short)10, (short)8); 
    	Util.arrayCopy(data, (short)(start_offset+8), temp, (short)0, (short)10);
    	switch(type)
    	{
    		case OFFSET_P1_ENC:
    			encrypt(temp, (short)10,temp,(short)0);
    			Util.arrayCopy(temp,(short)10, data, (short) start_offset, len_data);
    			return (short)8;
    		case OFFSET_P1_DEC:
    			decrypt(temp,(short)10, temp, (short)0);
    			Util.arrayCopy(temp,(short)10, data, (short) start_offset, len_data);
    			return (short)8;
    		default:
    			return (short)-1;
    	}
    }


}
