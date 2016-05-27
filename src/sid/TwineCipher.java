package sid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.crypto.KeyEncryption;
/**
 * The TWINE Cipher implementation
 * @author Alberto-PC
 *
 */
public class TwineCipher implements IConsts{
	
	/**
	 * The 80 bits of cipher twine
	 */
	public static final short MAX_MEMORY_TEMPORARY=32;
	private static  TwineCipher ref_twineCipher_80 = null;
	private static  TwineCipher ref_twineCipher_128 = null;
	public  byte[] temp   =  JCSystem.makeTransientByteArray(MAX_MEMORY_TEMPORARY,JCSystem.CLEAR_ON_DESELECT);
	public  byte[] rk 	= JCSystem.makeTransientByteArray((short) ((short)36*8),JCSystem.CLEAR_ON_DESELECT); 
	 					//for storing the session key
	private final  byte  [] roundconst = 
		{
				0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28, 0x13, 0x26,
				0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0e, 0x1c, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0b,
		};
	private final  short [] shufinv = {1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12};
	private final  short [] shuf = { 5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14};
	private final  byte	 [] sbox = {0x0C, 0x00, 0x0F, 0x0A, 0x02, 0x0B, 0x09, 0x05, 0x08, 0x03, 0x0D, 0x07, 0x01, 0x0E, 0x06, 0x04};
	private final  byte	 [] data_enc  = new byte[16];
	
	public static TwineCipher getInstance(byte type,byte[] key)
	{
		switch(type)
		{
			case TWINE_CIPHER_80:
				if(ref_twineCipher_80 != null)
					return ref_twineCipher_80;
				ref_twineCipher_80 =  new TwineCipher(key,TWINE_CIPHER_80);
				return ref_twineCipher_80;
			case TWINE_CIPHER_128:
				if(ref_twineCipher_128 != null)
					return ref_twineCipher_128;
				ref_twineCipher_128 =  new TwineCipher(key,TWINE_CIPHER_128);
				return ref_twineCipher_128;
			default:
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		return null;
	}
	
	public static TwineCipher getInstance(byte type)
	{
		switch(type)
		{
			case TWINE_CIPHER_80:
				if(ref_twineCipher_80 != null)
					return ref_twineCipher_80;
				ref_twineCipher_80 =  new TwineCipher();
				return ref_twineCipher_80;
			case TWINE_CIPHER_128:
				if(ref_twineCipher_128 != null)
					return ref_twineCipher_128;
				ref_twineCipher_128 =  new TwineCipher();
				return ref_twineCipher_128;
			default:
				ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		}
		ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		return null;
	}
	private TwineCipher(byte[] key,byte keySize)
	{
		switch(keySize)
		{
			case TWINE_CIPHER_80:
				expand80Key(key);
				break;
			case TWINE_CIPHER_128:
				expand128Key(key);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}
	private TwineCipher()
	{
		
	}
	
	private void expand80Key(byte[] key)
	{
		short len_x = 20;
		short key_size = 10;
		short iterator = 0,iterator2=0;;
		byte temp_val=-1;
		byte temp_val2=-1,temp_val3=-1,temp_val4=-1;
		short sh=0;
		// reset the array
		Util.arrayFillNonAtomic(temp, (short)0, (short)20, IConsts.UNTOUCHED_VALUE);
		
		unrowl80ExpandKey(key);
		
		for ( iterator = 0 ; iterator < 35;iterator ++)
		{
			rk[(short)(iterator * 8 + 0)] = temp[1];
			rk[(short)(iterator * 8 + 1)] = temp[3];
			rk[(short)(iterator * 8 + 2)] = temp[4];
			rk[(short)(iterator * 8 + 3)] = temp[6];
			rk[(short)(iterator * 8 + 4)] = temp[13];
			rk[(short)(iterator * 8 + 5)] = temp[14];
			rk[(short)(iterator * 8 + 6)] = temp[15];
			rk[(short)(iterator * 8 + 7)] = temp[16];
			
			temp[1] ^= sbox[temp[0]];
			temp[4] ^= sbox[temp[16]];
			temp_val = roundconst[iterator];
			temp[7] ^= temp_val >> 3;
			temp[19] ^= temp_val & 7;
			
			temp_val  = temp[0];
			temp_val2 = temp[1];
			temp_val3 = temp[2];
			temp_val4 = temp[3];
			
			for (iterator2 = 0 ; iterator2 < 4;iterator2++)
			{
				sh 					= (short)(iterator2*4);
				temp[sh]  			= temp[(short)(sh+4)];
				temp[(short)(sh+1)] = temp[(short)(sh+5)];
				temp[(short)(sh+2)] = temp[(short)(sh+6)];
				temp[(short)(sh+3)] = temp[(short)(sh+7)];
			}
			
			temp[16]   = temp_val2;
			temp[17]   = temp_val3;
			temp[18]   = temp_val4;
			temp[19]   = temp_val;
		
		}
		rk[(short)(35 * 8 + 0)] = temp[1];	
		rk[(short)(35 * 8 + 1)] = temp[3];	
		rk[(short)(35 * 8 + 2)] = temp[4];	
		rk[(short)(35 * 8 + 3)] = temp[6];	
		rk[(short)(35 * 8 + 4)] = temp[13];	
		rk[(short)(35 * 8 + 5)] = temp[14];	
		rk[(short)(35 * 8 + 6)] = temp[15];	
		rk[(short)(35 * 8 + 7)] = temp[16];	
		
	}
	private void expand128Key(byte[] key)
	{
		
	}

	public byte[] encrypt(byte[] src,byte[] dest,short len_src)
	{
		Util.arrayFillNonAtomic(temp, (short)0, (short)32, IConsts.UNTOUCHED_VALUE); //reset all values 
		                                           // 16 bytes for first part
												  // 16 bytes for next
		short iterator=0,iterator2=0,iterator3=0;
		short START_ITERATOR = 16;
		for( iterator = 0 ; iterator < len_src ; iterator++)
		{
			temp[(short)(2*iterator)] = (byte)((short) (src[iterator] & 0x00FF) >> 4);
			temp[(short)(2*iterator+1)] = (byte)((short) (src[iterator] & 0x00FF) & 0x0F);
		}
			
		for ( iterator = 0 ; iterator < 35 ; iterator ++)
		{
			for ( iterator2 = 0 ; iterator2 < 8 ; iterator2 ++)
			{
				temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)] ^ rk[(short)(iterator*8+iterator2)]]; 
						
			}
			
			for (iterator3 = 0 ; iterator3 < 16;iterator3++)
			{
				temp[(short)(shuf[iterator3]+16)] = temp[(short)(iterator3)];
			}
			Util.arrayCopy(temp, (short)16, temp, (short)0, (short)16);
		}
		iterator = 35;
		for (iterator2 = 0; iterator2 < 8 ;iterator2++)
		{
			temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)]^ rk[(short)(iterator*8+iterator2)]]; 		
		}
		
		for ( iterator = 0 ;iterator < 8 ;iterator++)
		{
			temp[(short)(24+iterator)] = (byte)(temp[(short)(2*iterator)] << 4 | temp[(short)(2*iterator + 1)]);
		}
		Util.arrayCopy(temp, (short)24, dest, (short)(ISO7816.OFFSET_CDATA), (short)8);
		return temp; // returns bytes from 24 to 32
	}
	public byte[] decrypt(byte[] src,byte[] dest,short len_src)
	{
		// for this alg len_src is always 8 
		Util.arrayFillNonAtomic(temp, (short)0, (short)32, IConsts.UNTOUCHED_VALUE); //reset all values 
		short iterator=0,iterator2=0,iterator3=0;
		short START_ITERATOR = 16;
		for( iterator = 0 ; iterator < len_src ; iterator++)
		{
			temp[(short)(2*iterator)] = (byte)((short) (src[iterator] & 0x00FF) >> 4);
			temp[(short)(2*iterator+1)] = (byte)((short) (src[iterator] & 0x00FF) & 0x0F);
		}
		
		for ( iterator = 35 ; iterator > 0 ; iterator --)
		{
			for ( iterator2 = 0 ; iterator2 < 8 ; iterator2 ++)
			{
				temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)]^ rk[(short)(iterator*8+iterator2)]];
			}
			
			for (iterator3 = 0 ; iterator3 < 16;iterator3++)
			{
				temp[(short)(shufinv[iterator3]+16)] = temp[(short)(iterator3)];
			}
			Util.arrayCopy(temp, (short)16, temp, (short)0, (short)16);
		}
		//FINAL
		iterator = 0;
		for (iterator2 = 0; iterator2 < 8 ;iterator2++)
		{
			temp[(short)(2*iterator2+1)] ^= sbox[temp[(short)(2*iterator2)]^ rk[(short)(iterator*8+iterator2)]];
		}
		
		for ( iterator = 0 ;iterator < 8 ;iterator++)
		{
			temp[(short)(24+iterator)] = (byte)(temp[(short)(2*iterator)] << 4 | temp[(short)(2*iterator + 1)]);
		}
		Util.arrayCopy(temp, (short)24, dest, (short)(ISO7816.OFFSET_CDATA), (short)8);
		return temp; // returns bytes from 24 to 32 indexes
	}

    public short process(byte type,byte[] data,short start_offset,short len_data)
    {
    	Util.arrayCopy(data, start_offset, data_enc, (short) 0, len_data);
    	switch(type)
    	{
    		case OFFSET_P1_ENC:
    			encrypt(data_enc, data, len_data);
    			return (short)8;
    		case OFFSET_P1_DEC:
    			decrypt(data_enc, data, len_data);
    			return (short)8;
    		case OFFSET_P1_GEN:
    			expand80Key(data_enc);
    			return 10;
    		default:
    			return (short)-1;
    	}
    	
    }

    private void unrowl80ExpandKey(byte[] key)
    {
		temp[(short)(2*0)] = (byte)((short) (key[0] & 0x00FF) >> 4);
		temp[(short)(2*0 + 1)] = (byte)((short) (key[0] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*1)] = (byte)((short) (key[1] & 0x00FF) >> 4);
		temp[(short)(2*1 + 1)] = (byte)((short) (key[1] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*2)] = (byte)((short) (key[2] & 0x00FF) >> 4);
		temp[(short)(2*2 + 1)] = (byte)((short) (key[2] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*3)] = (byte)((short) (key[3] & 0x00FF) >> 4);
		temp[(short)(2*3 + 1)] = (byte)((short) (key[3] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*4)] = (byte)((short) (key[4] & 0x00FF) >> 4);
		temp[(short)(2*4 + 1)] = (byte)((short) (key[4] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*5)] = (byte)((short) (key[5] & 0x00FF) >> 4);
		temp[(short)(2*5 + 1)] = (byte)((short) (key[5] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*6)] = (byte)((short) (key[6] & 0x00FF) >> 4);
		temp[(short)(2*6 + 1)] = (byte)((short) (key[6] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*7)] = (byte)((short) (key[7] & 0x00FF) >> 4);
		temp[(short)(2*7 + 1)] = (byte)((short) (key[7] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*8)] = (byte)((short) (key[8] & 0x00FF) >> 4);
		temp[(short)(2*8 + 1)] = (byte)((short) (key[8] & 0x00FF) & 0x0F); 	
		
		temp[(short)(2*9)] = (byte)((short) (key[9] & 0x00FF) >> 4);
		temp[(short)(2*9 + 1)] = (byte)((short) (key[9] & 0x00FF) & 0x0F); 	
    }
}
