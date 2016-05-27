package sid;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class LBlockCipher implements IConsts
{
	
	public static final byte  LBLOCK_NBROUNDS =  32;
	public static final byte  LBLOCK_KEY_SIZE =  80;
	public static final short MEMORY_OUTPUT=32*4;
	public static final short MEMORY_TEMPORARY=32;	
	
	
	final byte[] S0 = { 14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5};
	final byte[] S1 = { 4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3 };
	final byte[] S2 = { 1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10 };
	final byte[] S3 = { 7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1 };
	final byte[] S4 = { 14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3 };
	final byte[] S5 = { 2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5 };
	final byte[] S6 = { 11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2 };
	final byte[] S7 = { 13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6 };
	final byte[] S8 = { 8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3 };
	final byte[] S9 = { 11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6 };	
	
	
	public  byte[] output    =  null;
	public  byte[] temp  	 =  null;
	
	private static LBlockCipher m_instance_Cipher = null;
	
	private LBlockCipher()
	{
		  output    =  JCSystem.makeTransientByteArray(MEMORY_OUTPUT,JCSystem.CLEAR_ON_DESELECT); 
	      temp  	 =  JCSystem.makeTransientByteArray(MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT); 
	}
	public void keySchedule(byte[] key,short start_offset)
	{
		// use for keyR offset temp [0 - 3 ]
		short i = 0 ;
		output[(short)(0*4+3)] = key[(short)(9 + start_offset)];
		output[(short)(0*4+2)] = key[(short)(8 + start_offset)];
		output[(short)(0*4+1)] = key[(short)(7 + start_offset)];
		output[(short)(0*4+0)] = key[(short)(6 + start_offset)];
		
		for ( i = 1;i<32;i++)
		{
			temp[3] = key[(short)(9 + start_offset)];
			temp[2] = key[(short)(8 + start_offset)];
			temp[1] = key[(short)(7 + start_offset)];
			temp[0] = key[(short)(6 + start_offset)];
			
			key[(short)(9 + start_offset)] = (byte) ((((key[(short)(6 + start_offset)] & 0x07) << 5) 
											& 0xE0) ^ (((key[(short)(5 + start_offset)] & 0xF8) >> 3) & 0x1F));
			key[(short)(8 + start_offset)] = (byte) ((((key[(short)(5 + start_offset)]
											& 0x07) << 5) & 0xE0) ^ (((key[(short)(4 + start_offset)] & 0xF8) >> 3) & 0x1F));
			key[(short)(7 + start_offset)] = (byte) ((((key[(short)(4 + start_offset)] 
											& 0x07) << 5) & 0xE0) ^ (((key[(short)(3 + start_offset)] & 0xF8) >> 3) & 0x1F));
			key[(short)(6 + start_offset)] = (byte) ((((key[(short)(3 + start_offset)] 
											& 0x07) << 5) & 0xE0) ^ (((key[(short)(2 + start_offset)] & 0xF8) >> 3) & 0x1F));
			key[(short)(5 + start_offset)] = (byte) ((((key[(short)(2 + start_offset)] & 0x07) << 5) 
											& 0xE0) ^ (((key[(short)(1 + start_offset)] & 0xF8) >> 3) & 0x1F));
			
			key[(short)(4 + start_offset)] = (byte) ((((key[(short)(1 + start_offset)] & 0x07) << 5) 
											& 0xE0) ^ (((key[(short)(0 + start_offset)] & 0xF8) >> 3) & 0x1F));
			key[(short)(3 + start_offset)] = (byte) ((((key[(short)(0 + start_offset)] & 0x07) << 5) 
											& 0xE0) ^ (((temp[3] & 0xF8) >> 3) & 0x1F));
			key[(short)(2 + start_offset)] = (byte) ((((temp[3] & 0x07) << 5) & 0xE0) ^ (((temp[2] & 0xF8) >> 3) & 0x1F));
			key[(short)(1 + start_offset)] = (byte) ((((temp[2] & 0x07) << 5) & 0xE0) ^ (((temp[1] & 0xF8) >> 3) & 0x1F));
			key[(short)(0 + start_offset)] = (byte) ((((temp[1] & 0x07) << 5) & 0xE0) ^ (((temp[0] & 0xF8) >> 3) & 0x1F));
			
			key[(short)(9 + start_offset)] = (byte) ((S9[((key[(short)(9 + start_offset)] >> 4) & 0x0F)] << 4)
											^ S8[(key[(short)(9 + start_offset)] & 0x0F)]);

			key[(short)(6 + start_offset)] = (byte) (key[(short)(6 + start_offset)] ^ ((i >> 2) & 0x07));
			key[(short)(5 + start_offset)] = (byte) (key[(short)(5 + start_offset)] ^ ((i & 0x03) << 6));

			output[(short)(i*4 + 3)] =  key[(short)(9 + start_offset)];
			output[(short)(i*4 + 2)] =  key[(short)(8 + start_offset)];
			output[(short)(i*4 + 1)] =  key[(short)(7 + start_offset)];
			output[(short)(i*4 + 0)] =  key[(short)(6 + start_offset)];;
		}
	}
	public void OneRound(byte[] x,byte[] k,short offset,short offset_x)
	{
		// t  - from 5 - 8 tmp from 9 to 12
		//	u8 t[4], tmp[4];

		temp[9]  = x[(short)(4 + offset_x)];
		temp[10] = x[(short)(5 + offset_x)];
		temp[11] = x[(short)(6 + offset_x)];
		temp[12] = x[(short)(7 + offset_x)];

		x[(short)(4 + offset_x)] ^= k[offset];
		x[(short)(5 + offset_x)] ^= k[(short)(offset+1)];
		x[(short)(6 + offset_x)] ^= k[(short)(offset+2)];
		x[(short)(7 + offset_x)] ^= k[(short)(offset+3)];

		x[(short)(4 + offset_x)] = (byte) (((S1[((x[(short)(4 + offset_x)]) >> 4) & 0x0F]) << 4) 
								^ S0[(x[(short)(4 + offset_x)] & 0x0F)]);
		x[(short)(5 + offset_x)] = (byte) (((S3[((x[(short)(5 + offset_x)]) >> 4) & 0x0F]) << 4) 
								^ S2[(x[(short)(5 + offset_x)] & 0x0F)]);
		x[(short)(6 + offset_x)] = (byte) (((S5[((x[(short)(6 + offset_x)]) >> 4) & 0x0F]) << 4) 
								^ S4[(x[(short)(6 + offset_x)] & 0x0F)]);
		x[(short)(7 + offset_x)]= (byte) (((S7[((x[(short)(7 + offset_x)]) >> 4) & 0x0F]) << 4)
								^  S6[(x[(short)(7 + offset_x)] & 0x0F)]);

		temp[5] = (byte) (((x[(short)(4 + offset_x)] >> 4) & 0x0F) ^ (x[(short)(5 + offset_x)] & 0xF0));
		temp[6] = (byte) ((x[(short)(4 + offset_x)] & 0x0F) ^ ((x[(short)(5 + offset_x)] & 0x0F) << 4));
		temp[7] = (byte) (((x[(short)(6 + offset_x)] >> 4) & 0x0F) ^ (x[(short)(7 + offset_x)] & 0xF0));
		temp[8] = (byte) ((x[(short)(6 + offset_x)] & 0x0F) ^ ((x[(short)(7 + offset_x)] & 0x0F) << 4));

		x[(short)(4 + offset_x)] = (byte) (x[(short)(3 + offset_x)] ^ temp[5]);
		x[(short)(5 + offset_x)] = (byte) (x[(short)(0 + offset_x)] ^ temp[6]);
		x[(short)(6 + offset_x)] = (byte) (x[(short)(1 + offset_x)] ^ temp[7]);
		x[(short)(7 + offset_x)] = (byte) (x[(short)(2 + offset_x)] ^ temp[8]);

		x[(short)(0 + offset_x)] = temp[9];
		x[(short)(1 + offset_x)] = temp[10];
		x[(short)(2 + offset_x)] = temp[11];
		x[(short)(3 + offset_x)] = temp[12];


	}
	public void encrypt(byte[] x,short offset_x)
	{
		short i;
		for (i = 0; i<32; i++)
		{
			OneRound(x,output,(short)(4*i),offset_x);
		}
	}
	public void OneRoundInv(byte[] y, byte[] k,short offset,short offset_y)
	{
		// t  - from 5 - 8 tmp from 9 to 12
		//	u8 t[4], tmp[4];

		temp[9]  = y[(short)(0 + offset_y)];
		temp[10] = y[(short)(1 + offset_y)];
		temp[11] = y[(short)(2 + offset_y)];
		temp[12] = y[(short)(3 + offset_y)];

		y[(short)(0 + offset_y)] = (byte) (y[(short)(0 + offset_y)] ^ k[offset]);
		y[(short)(1 + offset_y)] = (byte) (y[(short)(1 + offset_y)] ^ k[(short)(offset+1)]);
		y[(short)(2 + offset_y)] = (byte) (y[(short)(2 + offset_y)] ^ k[(short)(offset+2)]);
		y[(short)(3 + offset_y)] = (byte) (y[(short)(3 + offset_y)] ^ k[(short)(offset+3)]);


		y[(short)(0 + offset_y)] = (byte) (((S1[((y[(short)(0 + offset_y)]) >> 4) & 0x0F]) << 4) ^ S0[(y[(short)(0 + offset_y)] & 0x0F)]);
		y[(short)(1 + offset_y)] = (byte) (((S3[((y[(short)(1 + offset_y)]) >> 4) & 0x0F]) << 4) ^ S2[(y[(short)(1 + offset_y)] & 0x0F)]);
		y[(short)(2 + offset_y)] = (byte) (((S5[((y[(short)(2 + offset_y)]) >> 4) & 0x0F]) << 4) ^ S4[(y[(short)(2 + offset_y)] & 0x0F)]);
		y[(short)(3 + offset_y)] = (byte) (((S7[((y[(short)(3 + offset_y)]) >> 4) & 0x0F]) << 4) ^ S6[(y[(short)(3 + offset_y)] & 0x0F)]);


		temp[5] = (byte) (((y[(short)(0 + offset_y)] >> 4) & 0x0F) ^ (y[(short)(1 + offset_y)] & 0xF0));
		temp[6] = (byte) ((y[(short)(0 + offset_y)] & 0x0F) ^ ((y[(short)(1 + offset_y)] & 0x0F) << 4));
		temp[7] = (byte) (((y[(short)(2 + offset_y)] >> 4) & 0x0F) ^ (y[(short)(3 + offset_y)] & 0xF0));
		temp[8] = (byte) ((y[(short)(2 + offset_y)] & 0x0F) ^ ((y[(short)(3 + offset_y)] & 0x0F) << 4));
	
		y[(short)(0 + offset_y)] = (byte) (y[(short)(5 + offset_y)] ^ temp[6]);
		y[(short)(1 + offset_y)] = (byte) (y[(short)(6 + offset_y)] ^ temp[7]);
		y[(short)(2 + offset_y)] = (byte) (y[(short)(7 + offset_y)] ^ temp[8]);
		y[(short)(3 + offset_y)] = (byte) (y[(short)(4 + offset_y)] ^ temp[5]);

		// PARTIE GAUCHE
		y[(short)(4 + offset_y)] = temp[9];
		y[(short)(5 + offset_y)] = temp[10];
		y[(short)(6 + offset_y)] = temp[11];
		y[(short)(7 + offset_y)] = temp[12];


	}
	public void decrypt(byte[] x,short offset_x)
	{
		short i;

		for (i = 31; i >= 0; i--)
		{
			OneRoundInv(x,output,(short)(i*4),offset_x);
		}
	}

    public short process(byte type,byte[] data,short start_offset,short len_data)
    {
    	Util.arrayCopy(data, start_offset, temp, (short) 16, len_data);
    	switch(type)
    	{
    		case OFFSET_P1_ENC:
    			encrypt(temp,(short)(16));
    			Util.arrayCopy(temp,(short) 16, data, (short) start_offset, len_data);
    			return (short)8;
    		case OFFSET_P1_DEC:
    			decrypt(temp,(short)(16));
    			Util.arrayCopy(temp,(short) 16, data, (short) start_offset, len_data);
    			return (short)8;
    		case OFFSET_P1_GEN:
    			keySchedule(temp,(short)(16));
    			Util.arrayCopy(temp,(short) 16, data, (short) start_offset, len_data);
    			return 10;
    		default:
    			return (short)-1;
    	}
    	
    }
	public static LBlockCipher getInstance()
	{
		if(m_instance_Cipher == null)
			m_instance_Cipher =  new LBlockCipher();
		return m_instance_Cipher;
	}

}
