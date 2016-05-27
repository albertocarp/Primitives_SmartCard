package sid;


import com.sun.javacard.crypto.ad;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class JCMath {
  
	private Cipher mRsaCipherForSquaring;
	private Cipher mRsaCipherModPow;
	private RSAPublicKey mRsaPublicKekForSquare;
	private RSAPublicKey mRsaPublicKeyModPow;
	private RSAPrivateKey mRsaPrivateKeyModPow;
	private byte[] tempBuffer;
	private byte[] ram_x;
	private byte[] ram_y;
	private byte[] ram_y_prime;	
	public final byte[] SQUARE_EXPONENT = new byte[] { 0x02 };
	
	boolean SIMULATOR=false;
	public boolean test_mode = false;
	
	public JCMath(byte[] modulus,short xOffset,short xLength)
	{
		initializeKeys();
		Util.arrayFillNonAtomic(tempBuffer, Configuration.TEMP_OFFSET_MODULUS, Configuration.LENGTH_RSAOBJECT_MODULUS , (byte)0x00);
		Util.arrayCopy(modulus,xOffset,tempBuffer,(short)(Configuration.TEMP_OFFSET_MODULUS+Configuration.LENGTH_RSAOBJECT_MODULUS - xLength),xLength);
		updateModulus(modulus, xOffset, xLength);
	}
	private void initializeKeys()
	{
		tempBuffer = JCSystem.makeTransientByteArray((short)414,JCSystem.CLEAR_ON_DESELECT);  // 256 + 414 670 bytes
		ram_x = JCSystem.makeTransientByteArray(Configuration.LENGTH_RSAOBJECT_MODULUS,JCSystem.CLEAR_ON_DESELECT); 
		ram_y = JCSystem.makeTransientByteArray(Configuration.LENGTH_RSAOBJECT_MODULUS,JCSystem.CLEAR_ON_DESELECT); 
		ram_y_prime = JCSystem.makeTransientByteArray(Configuration.LENGTH_RSAOBJECT_MODULUS,JCSystem.CLEAR_ON_DESELECT); 
		if(!SIMULATOR)
		{		
			mRsaPublicKekForSquare = (RSAPublicKey) KeyBuilder.buildKey(
					KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
			mRsaPublicKeyModPow = (RSAPublicKey) KeyBuilder.buildKey(
					KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
			mRsaPrivateKeyModPow = (RSAPrivateKey) KeyBuilder.buildKey(
					KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
			mRsaCipherModPow = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
			mRsaCipherForSquaring = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
			mRsaPublicKekForSquare.setExponent(SQUARE_EXPONENT, (short) 0x00,
					(short) 0x01);
		}	
	}
	private void clearKeys()
	{
		mRsaPrivateKeyModPow.clearKey();
		mRsaPublicKeyModPow.clearKey();
		mRsaPublicKekForSquare.clearKey();
		mRsaPublicKekForSquare.setExponent(SQUARE_EXPONENT, (short) 0x00,
				(short) 0x01);
		
	}
	private void normalize()
	{
		clearKeys();
		updateModulus(tempBuffer, Configuration.TEMP_OFFSET_MODULUS, Configuration.LENGTH_MODULUS);
	}
	/**
	 * This function used internally to perform raw multiplication
	 * No checking is being done
	 */
	private byte[] multiply(byte[] x, short xOffset, short xLength, byte[] y,
	        short yOffset, short yLength,short tempOutoffset)
	{
		normalize();
	    //copy x value to temporary rambuffer
		Util.arrayFillNonAtomic(tempBuffer, tempOutoffset,(short) (Configuration.LENGTH_RSAOBJECT_MODULUS+tempOutoffset),(byte)0x00);
	    Util.arrayCopy(x, xOffset, tempBuffer, (short)(Configuration.LENGTH_RSAOBJECT_MODULUS - xLength), xLength);

	    // copy the y value to match th size of rsa_object
	    Util.arrayFillNonAtomic(ram_y, IConsts.OFFSET_START, (short) (Configuration.LENGTH_RSAOBJECT_MODULUS-1),(byte)0x00);
	    Util.arrayCopy(y,yOffset,ram_y,(short)(Configuration.LENGTH_RSAOBJECT_MODULUS - yLength),yLength);
	    
	    Util.arrayFillNonAtomic(ram_y_prime, IConsts.OFFSET_START, (short) (Configuration.LENGTH_RSAOBJECT_MODULUS-1),(byte)0x00);
	    Util.arrayCopy(y,yOffset,ram_y_prime,(short)(Configuration.LENGTH_RSAOBJECT_MODULUS - yLength),yLength);
	    
	    Util.arrayFillNonAtomic(ram_x, IConsts.OFFSET_START, (short) (Configuration.LENGTH_RSAOBJECT_MODULUS-1),(byte)0x00);
	    Util.arrayCopy(x,xOffset,ram_x,(short)(Configuration.LENGTH_RSAOBJECT_MODULUS - xLength),xLength);

	    // if x>y
	    if(this.isGreater(ram_x, IConsts.OFFSET_START, Configuration.LENGTH_RSAOBJECT_MODULUS, ram_y,IConsts.OFFSET_START, Configuration.LENGTH_MODULUS)>0)
	    {
	    	
	    	// x <- x-y
	        JBigInteger.subtract(ram_x,IConsts.OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS, ram_y,
	        		IConsts.OFFSET_START, Configuration.LENGTH_RSAOBJECT_MODULUS);
	    }
	    else
	    {
	    	
	    	// y <- y-x
	    	JBigInteger.subtract(ram_y_prime,IConsts.OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS, ram_x,
	    			IConsts.OFFSET_START, Configuration.LENGTH_MODULUS);
	    	 // ramy stores the (y-x) values copy value to ram_x
	    	Util.arrayCopy(ram_y_prime, IConsts.OFFSET_START,ram_x,IConsts.OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS);
	    	
	    }
	
		    //|x-y|2
		    mRsaCipherForSquaring.init(mRsaPublicKekForSquare, Cipher.MODE_ENCRYPT);
		    mRsaCipherForSquaring.doFinal(ram_x, IConsts.OFFSET_START, Configuration.LENGTH_RSAOBJECT_MODULUS, ram_x,
		    		IConsts.OFFSET_START); // OK
		    
		    // x^2
		    mRsaCipherForSquaring.doFinal(tempBuffer, tempOutoffset, Configuration.LENGTH_RSAOBJECT_MODULUS, tempBuffer, tempOutoffset); // OK
		   
		    // y^2
		    mRsaCipherForSquaring.doFinal(ram_y,IConsts.OFFSET_START, Configuration.LENGTH_RSAOBJECT_MODULUS, ram_y,IConsts.OFFSET_START); //OK 
		    
		    
		  
		    if (JBigInteger.add(ram_y, IConsts.OFFSET_START, Configuration.LENGTH_MODULUS, tempBuffer, tempOutoffset,
		            Configuration.LENGTH_MODULUS)) {
		    	  // y^2 + x^2 
		        JBigInteger.subtract(ram_y, IConsts.OFFSET_START, Configuration.LENGTH_MODULUS, tempBuffer,
		                Configuration.TEMP_OFFSET_MODULUS, Configuration.LENGTH_MODULUS);
		    } 
		  
		    
		    //  x^2 + y^2
		    if (JBigInteger.subtract(ram_y, IConsts.OFFSET_START, Configuration.LENGTH_MODULUS, ram_x, IConsts.OFFSET_START,
		            Configuration.LENGTH_MODULUS)) {
	
		        JBigInteger.add(ram_y, IConsts.OFFSET_START, Configuration.LENGTH_MODULUS, tempBuffer,
		                Configuration.TEMP_OFFSET_MODULUS, Configuration.LENGTH_MODULUS);
	    }
	    // ((x+y)^2 - x^2 -y^2)/2
	   JBigInteger.modular_division_by_2(ram_y, IConsts.OFFSET_START,Configuration. LENGTH_MODULUS, tempBuffer, Configuration.TEMP_OFFSET_MODULUS, Configuration.LENGTH_MODULUS);
	   return ram_y;
	}
	public void modMultiply(byte[] x, short xOffset, short xLength, byte[] y,
	        short yOffset, short yLength, short tempOutoffset) {
		
	   byte[] result = multiply(x,xOffset,xLength,y,yOffset,yLength,tempOutoffset);
	   if(xLength == UProveParameters.PSIZE_BYTES)	
		   Util.arrayCopy(result, IConsts.OFFSET_START, x, xOffset, Configuration.LENGTH_MODULUS);
	   else
	   {
		   ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	   }
	}

	public void updateModulus(byte[] modulus,short mOffset,short mLength)
	{	
		mRsaPublicKekForSquare.setModulus(tempBuffer, Configuration.TEMP_OFFSET_MODULUS, (short) Configuration.LENGTH_RSAOBJECT_MODULUS);
		mRsaPublicKeyModPow.setModulus(tempBuffer,  Configuration.TEMP_OFFSET_MODULUS, (short) Configuration.LENGTH_RSAOBJECT_MODULUS);
		mRsaPrivateKeyModPow.setModulus(tempBuffer,  Configuration.TEMP_OFFSET_MODULUS, (short) Configuration.LENGTH_RSAOBJECT_MODULUS);	
	}
	
	public byte[] modPow(byte[] x,short xOffset,short xLength,byte[] y,short yOffset,short yLength)
	{
		normalize();
		Util.arrayCopy(y, yOffset, tempBuffer, (short)(Configuration.TEMP_OFFSET_EXPONENT+4), yLength);
		Util.arrayFillNonAtomic(tempBuffer, Configuration.TEMP_OFFSET_EXPONENT, (byte)4,(byte)0x00);
		mRsaPrivateKeyModPow.setExponent(tempBuffer,Configuration.TEMP_OFFSET_EXPONENT, (short)(yLength+4));
		mRsaCipherModPow.init(mRsaPrivateKeyModPow, Cipher.MODE_DECRYPT);
		Util.arrayFillNonAtomic(tempBuffer,(short)0,(short)(Configuration.LENGTH_RSAOBJECT_MODULUS + Configuration.ADDITIONAL_PADDING),(byte)0x00);
		Util.arrayCopy(x,xOffset,tempBuffer,Configuration.TEMP_OFFSET_RSA, xLength);
		mRsaCipherModPow.doFinal(tempBuffer,Configuration.TEMP_OFFSET_RSA, (short) (Configuration.LENGTH_RSAOBJECT_MODULUS), tempBuffer,Configuration.TEMP_OFFSET_RSA);
		return tempBuffer;
	}
	public byte[] modPowFull(byte[] x,short xOffset,short xLength,byte[] y,short yOffset,short yLength)
	{
		normalize();
		Util.arrayCopy(y, yOffset, ram_y,IConsts.OFFSET_START,yLength);
		mRsaPrivateKeyModPow.setExponent(ram_y,IConsts.OFFSET_START,yLength);
		mRsaCipherModPow.init(mRsaPrivateKeyModPow, Cipher.MODE_DECRYPT);
		Util.arrayCopy(x,xOffset,ram_x,IConsts.OFFSET_START, xLength);
		mRsaCipherModPow.doFinal(ram_x,IConsts.OFFSET_START, (short) (Configuration.LENGTH_RSAOBJECT_MODULUS),ram_x,IConsts.OFFSET_START);
		return ram_x;
	}
    public short isGreater(byte[] x,short xOffset,short xLength,byte[] y ,short yOffset,short yLength)
    {
        // Beware: this part is not tested
        while(xLength>yLength) {
            if(x[xOffset++]!=0x00) {
                return 1; // x is greater
            }
            xLength--;
        }
        while(yLength>xLength) {
            if(y[yOffset++]!=0x00) {
                return -1; // y is greater
            }
            yLength--;
        }
        // Beware: this part is not tested END
        for(short i = 0; i < xLength; i++) {
            if (x[xOffset] != y[yOffset]) {
                short srcShort = (short)(x[xOffset]&(short)0xFF);
                short dstShort = (short)(y[yOffset]&(short)0xFF);
                return ( ((srcShort > dstShort) ? (byte)1 : (byte)-1));
            }
            xOffset++;
            yOffset++;
        }
        return 0;
    }

    public void square(byte[] x,short xOffset,short xLength,byte[] output,short outputOffset)
    {
    	 normalize();
    	 Util.arrayFillNonAtomic(ram_x, IConsts.OFFSET_START, (short) (Configuration.LENGTH_RSAOBJECT_MODULUS-1),(byte)0x00);
 	     Util.arrayCopy(x,xOffset,ram_x,(short)(Configuration.LENGTH_RSAOBJECT_MODULUS - xLength),xLength);
    	 mRsaCipherForSquaring.init(mRsaPublicKekForSquare, Cipher.MODE_ENCRYPT);
		 mRsaCipherForSquaring.doFinal(ram_x, IConsts.OFFSET_START, Configuration.LENGTH_RSAOBJECT_MODULUS, ram_x,
		    		IConsts.OFFSET_START); // OK
		 Util.arrayCopy(ram_x, IConsts.OFFSET_START,output , outputOffset, Configuration.LENGTH_MODULUS);
    }

    
}
