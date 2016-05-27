package sid;

import javacard.security.RandomData;

public class Configuration implements IConsts 
{
	public static final boolean inRAM = false;  
	
	public static final  short LENGTH_MODULUS = 128;
	
	public static short LENGTH_SECOND_MODULUS=20;
	
	public static final short LENGTH_RSAOBJECT_MODULUS = 128;
	
	public final static short ADDITIONAL_PADDING = 2;
	
	public  static final short MIN_POW_LENGTH = 24;
	
	public final static short LENGTH_MESSAGE_DIGEST = (short) 24	;
	
	public static final short LENGTH_PADDING_FOR_SQUARE_MULT = (short) (108);
	
	public static final  short TEMP_OFFSET_RSA = OFFSET_START + ADDITIONAL_PADDING;  // 2

	public  static final short TEMP_OFFSET_MODULUS =  TEMP_OFFSET_RSA + LENGTH_RSAOBJECT_MODULUS;// 2+128
	
	public  static final short TEMP_OFFSET_EXPONENT = (short) (TEMP_OFFSET_MODULUS + LENGTH_MODULUS); //258
	
	public static final short TEMP_EXP_MULTIPLY_RESULT = (short) (TEMP_OFFSET_RSA + TEMP_OFFSET_EXPONENT + MIN_POW_LENGTH); //258 + 24 + 128 = 406
	
	public  static short LENGTH_MAX_POW = 10; // only 10 bytes exponentiation supported by the card
	

	

	


}
