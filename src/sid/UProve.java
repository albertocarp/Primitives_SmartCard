package sid;

import com.sun.javacard.crypto.q;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.SignatureMessageRecovery;
import javacardx.crypto.Cipher;
import javacardx.external.MemoryAccess;
import javacardx.framework.math.BigNumber;
import javacardx.framework.util.ArrayLogic;
import sid.UProveParameters.UproveInternal;

public class UProve implements IConsts {
	
	UProveParameters parameters ;
	JCMath jcMath;
	public static short KEY_LENGTH=128;
	private static UProve m_Instance = null;
	public byte[] temp1 = new byte[256];
	public byte[] temp2 = new byte[160];
	RandomData m_random;
	final static short EXPONENT_LENGTH = (short) 128;
	final static short MODULUS_LENGTH = (short) 128;
	JBigInteger q = new JBigInteger(UProveParameters.PSIZE_BYTES, false);
	JBigInteger res = new JBigInteger(Configuration.LENGTH_RSAOBJECT_MODULUS, false);
	JBigInteger el = new JBigInteger(Configuration.LENGTH_RSAOBJECT_MODULUS, false);
	
	private void loadDefaultGroup()
	{
			setP(TestUProve.GROUP_P,OFFSET_START,UProveParameters.PSIZE_BYTES);
			setG(TestUProve.GROUP_G,OFFSET_START,UProveParameters.PSIZE_BYTES);
			setQ(TestUProve.GROUP_Q,OFFSET_START,UProveParameters.QSIZE_BYTES);
			
			setPI(TestUProve.PI, OFFSET_START, (short)TestUProve.PI.length);
			setTI(TestUProve.TI, OFFSET_START, (short)TestUProve.TI.length);
			setEi(TestUProve.E,  OFFSET_START, (short)TestUProve.E.length);
				
			setUidH(TestUProve.UIDH,OFFSET_START,(short)TestUProve.UIDH.length);
			setUidp(TestUProve.UIDP,OFFSET_START,(short)TestUProve.UIDP.length);
			setS(TestUProve.S,OFFSET_START,(short)TestUProve.S.length);
			
			// set pub_key
			setPubKey(TestUProve.G0, OFFSET_START,(short)TestUProve.G0.length, (byte)0);		
			setPubKey(TestUProve.G1, OFFSET_START,(short)TestUProve.G1.length, (byte)1);
			setPubKey(TestUProve.G2, OFFSET_START,(short)TestUProve.G2.length, (byte)2);
			setPubKey(TestUProve.G3, OFFSET_START,(short)TestUProve.G3.length, (byte)3);
			setPubKey(TestUProve.G4, OFFSET_START,(short)TestUProve.G4.length, (byte)4);
			setPubKey(TestUProve.G5, OFFSET_START,(short)TestUProve.G5.length, (byte)5);
			setPubKey(TestUProve.GT, OFFSET_START,(short)TestUProve.GT.length, (byte)6);
			
			setAtribute(TestUProve.A1, OFFSET_START, (short)TestUProve.A1.length, (short)TestUProve.A1.length, OFFSET_START);
			setAtribute(TestUProve.A2, OFFSET_START, (short)TestUProve.A2.length, (short)TestUProve.A2.length, (short)1);
			setAtribute(TestUProve.A3, OFFSET_START, (short)TestUProve.A3.length, (short)TestUProve.A3.length, (short)2);
			setAtribute(TestUProve.A4, OFFSET_START, (short)TestUProve.A4.length, (short)TestUProve.A4.length, (short)3);
			setAtribute(TestUProve.A5, OFFSET_START, (short)TestUProve.A5.length, (short)TestUProve.A5.length, (short)4);
		
			computeXt();
	}
	
	private UProve()
	{
		
		parameters = new UProveParameters();
		//loadDefaultGroup();
	}

	public void run()
	{
		generateRandomAlphaBeta();
		proverPrecomputation();
		issuerPrecomputation();
		generateFirstMessage();
        generateSecondMessage();
		generateThirdMessage();	
		computeTokenId();
	 	verify();
	}
	public static UProve getInstance()
	{
		if(m_Instance == null)
			m_Instance = new UProve();
		return m_Instance;
	}
	public void setP(byte[] val,short offset,short length)
	{
	
		Util.arrayCopy(val,offset,parameters.p,OFFSET_START, length);
		Util.arrayCopy(val,offset,parameters.p_minus_two,OFFSET_START, length);
		parameters.p_minus_two[(short)(length-1)] -= 2; 
		if(jcMath == null)
		{
			jcMath = new JCMath(parameters.p,IConsts.OFFSET_START,UProveParameters.PSIZE_BYTES);
		}
	}
	public void setQ(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val,offset,parameters.q,OFFSET_START, length);
		Util.arrayCopy(val,offset,parameters.q_minus2,OFFSET_START, length);
		parameters.q_minus2[(short)(length-1)] -= 2; 
	}
	public void setPI(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset,parameters.PI,OFFSET_START,length);
		parameters.P1_LENGTH = length;	
	}
	public void setTI(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset,parameters.TI,OFFSET_START,length);
		parameters.T1_LENGTH = length;
	}
	public void setG(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val,offset,parameters.g,OFFSET_START, length);
	}
	public void setUidp(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val,offset,parameters.UID_P,OFFSET_START, length);
		parameters.UID_P_LENGTH = length;
	} 
	public void setEi(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset, parameters.e_i,OFFSET_START, length);
	}
	public void setUidH(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset,parameters.UID_H,OFFSET_START,length);
		parameters.UID_H_LENGTH = length;	
	}
	public void setS(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset,parameters.S,OFFSET_START,length);
		parameters.S_LENGTH = length;
	}
	public void setGamma(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset,parameters.gamma,OFFSET_START,length);
	}
	public void setSigmaZ(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset,parameters.sigma_z,OFFSET_START,length);
	}
	public void setRandom()
	{
	   Util.arrayCopy(TestUProve.ALPHA, OFFSET_START, parameters.alpha, OFFSET_START, (short)20);
	   Util.arrayCopy(TestUProve.BETA1, OFFSET_START, parameters.beta1, OFFSET_START, (short)20);
	   Util.arrayCopy(TestUProve.BETA2, OFFSET_START, parameters.beta2, OFFSET_START, (short)20);
	   Util.arrayCopy(TestUProve.ALPHAINVERSE, OFFSET_START, parameters.alpha_minus_one, OFFSET_START, (short)20);
	   Util.arrayCopy(TestUProve.W, OFFSET_START, parameters.w, OFFSET_START, (short)20);
	   Util.arrayCopy(TestUProve.Y0, OFFSET_START, parameters.y0, OFFSET_START, (short)20);
	}

	public void setSigmaZPrime(byte[] val,short offset,short length)
	{
		Util.arrayCopy(val, offset,parameters.sigma_s_prime,OFFSET_START,length);
	}
	
	private void generateRandomAlphaBeta()
	{
		RandomData data =  RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		data.generateData(parameters.alpha, OFFSET_START, UProveParameters.QSIZE_BYTES);
		data.generateData(parameters.beta1, OFFSET_START, UProveParameters.QSIZE_BYTES);
		data.generateData(parameters.beta2, OFFSET_START, UProveParameters.QSIZE_BYTES);
	}

	public byte[] getUidH()
	{
		return parameters.UID_H;
	}
	public byte[] getP()
	{
		return parameters.p;
	}
	public byte[] getQ()
	{
		return parameters.q;
	}
	public byte[] getG()
	{
		return parameters.g;
	}
	public byte[] getUidp()
	{
		return parameters.UID_P;
	}
	
	public byte[] getPI()
	{
		return this.parameters.PI;
	}
	
	public byte[] getTI()
	{
		return this.parameters.TI;
	}
	
	public byte[] getAttrCount()
	{
		return this.parameters.MAX_ATTR_BYTES;
	}
	
	public void setAtributeValue(byte[] data,short offset,short length,short index)
	{
		 Util.arrayCopy(data, offset,parameters.x_i[index].value,OFFSET_START,length);
	}
	
	public byte[] getAtributeValue(short index)
	{
		return this.parameters.x_i[index].value;
	}
		
	public void setAtribute(byte[] data,short offset,short length,short attr_size,short atrr_index)
	{
		//parameters.atributes[atrr_index].value.append(data,offset,length);
		Util.arrayCopy(data, offset,parameters.atributes[atrr_index].value,OFFSET_START,length);
		parameters.atributes[atrr_index].internal_size= attr_size;
		short i = 0 ;
		if(parameters.e_i[atrr_index] == 0x01)
		{
			i = setNumber(attr_size, data, offset, temp1, OFFSET_START);
			MessageDigest.getInstance(MessageDigest.ALG_SHA, false).doFinal(temp1,OFFSET_START,(short)(i), temp2, OFFSET_START);
			Util.arrayCopy(temp2, OFFSET_START,parameters.x_i[atrr_index].value,OFFSET_START,(short)20);
		}
		else
		{
			if(attr_size > UProveParameters.QSIZE_BYTES)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			for ( i = 0 ; i < (short)(UProveParameters.QSIZE_BYTES+1);i++)
			{
				parameters.x_i[atrr_index].internal_size=0;
			}
			Util.arrayCopy(data, offset,parameters.x_i[atrr_index].value,OFFSET_START,length);
		}
		
	}
	private void setInt(short num,byte[] array,short array_offset)
	{
		array[array_offset] = array[(short)(array_offset+1)]=0;
		array[(short)(array_offset+2)] = (byte) ((num >> 8) & 0xff);
		array[(short)(array_offset+3)] = (byte) (num & 0xff);
	}
	private short setNumber(short length,byte[] number,short number_offset,byte[] array,short array_offset)
	{
	    short offset = array_offset;
	    short i = 0;
	    short skip = 0;
	    short actualLength = 0;
	    if(length == UProveParameters.PSIZE_BYTES || length == UProveParameters.QSIZE_BYTES)
	    {
	    	 while(number[(short)(number_offset + skip)] == 0x00) 
	    		 skip++;
	    }
	    actualLength = (short) (length - skip+number_offset);
	    setInt(actualLength, array,array_offset);
		offset += 4;
		Util.arrayCopy(number, (short) (skip+number_offset),array,offset, actualLength);
		offset += actualLength;
		return offset;
	    
	}
	public void setPubKey(byte[] val,short offset,short length,byte atrIndex)
	{
		if(length != UProveParameters.PSIZE_BYTES)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		Util.arrayCopy(val,offset,parameters.g_i[atrIndex].value,OFFSET_START, length);
		parameters.g_i[atrIndex].internal_size = 0x00;
	}
	public byte[] getPubKey(byte index)
	{
		return parameters.g_i[index].value;
		
	}
	
	public void calculateGamma()
	{
		short i;
		Util.arrayCopy(parameters.g_i[0].value, OFFSET_START,parameters.gamma, OFFSET_START,UProveParameters.PSIZE_BYTES);
		short max_attr = (short)(parameters.MAX_ATTR+2);
		for ( i = 0 ; i < max_attr;i++)
		{
			byte[] data = jcMath.modPow(parameters.g_i[i].value, OFFSET_START, Configuration.LENGTH_RSAOBJECT_MODULUS, parameters.x_i[i].value,
					OFFSET_START, (short)UProveParameters.QSIZE_BYTES);
			Util.arrayCopy(data, Configuration.TEMP_OFFSET_RSA,parameters.temp_ram, OFFSET_START, UProveParameters.PSIZE_BYTES);
			jcMath.modMultiply(parameters.gamma, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.temp_ram,OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS,OFFSET_START);
		}	
	}
	public void computeXt()
	{
		short i,offset = 0;
		offset = setNumber((short) parameters.UID_P_LENGTH, parameters.UID_P,OFFSET_START, parameters.array,offset);
		offset = setNumber(UProveParameters.PSIZE_BYTES, parameters.p,OFFSET_START, parameters.array,offset);
		offset = setNumber(UProveParameters.QSIZE_BYTES, parameters.q,OFFSET_START, parameters.array,offset);
		offset = setNumber(UProveParameters.PSIZE_BYTES, parameters.g,OFFSET_START, parameters.array,offset);
		setInt((short)(parameters.MAX_ATTR+2),parameters.array,offset);
		offset +=4;
		for ( i = 0 ; i < (short)((parameters.MAX_ATTR)+2);i++)
		{
			offset = setNumber(UProveParameters.PSIZE_BYTES,parameters.g_i[i].value,OFFSET_START,parameters.array,offset);
		}
		setInt((short)(parameters.MAX_ATTR),parameters.array,offset);
		offset +=4;	
		for(i=0;i<(short)((parameters.MAX_ATTR));i++)
		{
			parameters.array[offset++] = parameters.e_i[i];
		}
		offset = setNumber((short)parameters.S_LENGTH, parameters.S,OFFSET_START, parameters.array,offset);
		MessageDigest.getInstance(MessageDigest.ALG_SHA, false).doFinal( parameters.array, OFFSET_START,offset, temp1,OFFSET_START);
		offset = 0;
		parameters.temp_ram[offset++] = 0x01;
		offset = setNumber((short) UProveParameters.QSIZE_BYTES,temp1,OFFSET_START, parameters.temp_ram,offset);
		offset = setNumber((short) parameters.T1_LENGTH ,parameters.TI,OFFSET_START, parameters.temp_ram,offset);
		MessageDigest.getInstance(MessageDigest.ALG_SHA, false).doFinal( parameters.temp_ram,OFFSET_START,offset,parameters.x_i[parameters.MAX_ATTR].value,OFFSET_START); 
	}
	
	public void precomputeInputs()
	{
		computeXt();
		calculateGamma();
	}
	public void issuerPrecomputation()
	{
		//calculeaza sigma_a si sigma_b
		
		RandomData data =  RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		data.generateData(parameters.w, OFFSET_START,UProveParameters.QSIZE_BYTES);
		
		byte[] res = jcMath.modPow(parameters.g, OFFSET_START,UProveParameters.PSIZE_BYTES,parameters.w,OFFSET_START,UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(res,Configuration.TEMP_OFFSET_RSA,parameters.sigma_a,OFFSET_START,UProveParameters.PSIZE_BYTES); // OK
	
		res = jcMath.modPow(parameters.gamma, OFFSET_START,UProveParameters.PSIZE_BYTES,parameters.w,OFFSET_START,UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(res,Configuration.TEMP_OFFSET_RSA,parameters.sigma_b,OFFSET_START,UProveParameters.PSIZE_BYTES); // OK*/
		
		
	}
	public void proverPrecomputation()
	{
		
		// calculates h
		byte[] result;
		
		byte[] res = jcMath.modPow(parameters.gamma, OFFSET_START,UProveParameters.PSIZE_BYTES,parameters.alpha,OFFSET_START,UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(res,Configuration.TEMP_OFFSET_RSA,parameters.h,OFFSET_START,UProveParameters.PSIZE_BYTES);
		
		
		//calculates sigma_z_prime
		
		result = jcMath.modPow(parameters.sigma_z, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.alpha, OFFSET_START, UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(result,Configuration.TEMP_OFFSET_RSA,parameters.sigma_s_prime,OFFSET_START,UProveParameters.PSIZE_BYTES);
		
		
		// t_b
		result = jcMath.modPow(parameters.sigma_s_prime, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.beta1, OFFSET_START, UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(result,Configuration.TEMP_OFFSET_RSA,parameters.t_b,OFFSET_START,UProveParameters.PSIZE_BYTES);
		
		result = jcMath.modPow(parameters.h, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.beta2, OFFSET_START, UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(result, Configuration.TEMP_OFFSET_RSA, parameters.temp_ram, OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS);
		jcMath.modMultiply(parameters.t_b, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.temp_ram, OFFSET_START, UProveParameters.PSIZE_BYTES, OFFSET_START);

		
		
		//calculates t_a
		
	    result = jcMath.modPow(TestUProve.G0, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.beta1, OFFSET_START, UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(result,Configuration.TEMP_OFFSET_RSA,parameters.t_a,OFFSET_START,UProveParameters.PSIZE_BYTES);
		
		result = jcMath.modPow(parameters.g, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.beta2, OFFSET_START, UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(result, Configuration.TEMP_OFFSET_RSA, parameters.temp_ram, OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS);
		
		jcMath.modMultiply(parameters.t_a, OFFSET_START, UProveParameters.PSIZE_BYTES, parameters.temp_ram, OFFSET_START, UProveParameters.PSIZE_BYTES, OFFSET_START);
		
		// calculate alpha^-1	  
		//jcMath.updateModulus(parameters.q ,OFFSET_START, UProveParameters.QSIZE_BYTES);
		//result = jcMath.modPow(parameters.alpha, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q_minus2,OFFSET_START,UProveParameters.QSIZE_BYTES);
		//Util.arrayCopy(result,OFFSET_START,parameters.alpha_minus_one,OFFSET_START,UProveParameters.QSIZE_BYTES);
		// calculates t_b*/
	
	}
	
	/**
	 * This is the actual protocol
	 */
	
	public void generateFirstMessage()
	{
		// 
	}
	public void generateSecondMessage()
	{
		
		//copiez t_a in sigma_a_prime
		Util.arrayCopy(parameters.t_a, OFFSET_START,parameters.sigma_a_prime, OFFSET_START, UProveParameters.PSIZE_BYTES);
		jcMath.modMultiply(parameters.sigma_a_prime, OFFSET_START, UProveParameters.PSIZE_BYTES,
		   parameters.sigma_a,OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS,OFFSET_START);
				
		Util.arrayCopy(parameters.t_b, OFFSET_START,parameters.sigma_b_prime, OFFSET_START, UProveParameters.PSIZE_BYTES);
		
		byte[] result = jcMath.modPow(parameters.sigma_b, OFFSET_START, UProveParameters.PSIZE_BYTES,parameters.alpha, OFFSET_START, UProveParameters.QSIZE_BYTES);
		
		Util.arrayCopy(result, Configuration.TEMP_OFFSET_RSA, parameters.temp_ram, OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS);
		jcMath.modMultiply(parameters.sigma_b_prime, OFFSET_START, UProveParameters.PSIZE_BYTES,
				 parameters.temp_ram, OFFSET_START,Configuration.LENGTH_RSAOBJECT_MODULUS,OFFSET_START);
		
		
		short offset = 0 ;
		offset = setNumber((short) UProveParameters.PSIZE_BYTES, parameters.h,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) parameters.P1_LENGTH, parameters.PI,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) UProveParameters.PSIZE_BYTES, parameters.sigma_s_prime,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) UProveParameters.PSIZE_BYTES, parameters.sigma_a_prime,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) UProveParameters.PSIZE_BYTES, parameters.sigma_b_prime,OFFSET_START, parameters.array,offset);
		MessageDigest.getInstance(MessageDigest.ALG_SHA, false).doFinal( parameters.array, OFFSET_START,offset, temp1,OFFSET_START);
	   	if(jcMath.isGreater(temp1, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q, OFFSET_START,  UProveParameters.QSIZE_BYTES)>0)
	   	{
	   	   JBigInteger.subtract(temp1, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q, OFFSET_START,  UProveParameters.QSIZE_BYTES);
	   	}
	   	Util.arrayCopy(temp1, OFFSET_START,parameters.sigma_c_prime,OFFSET_START,UProveParameters.QSIZE_BYTES);
		Util.arrayCopy(temp1, OFFSET_START,parameters.sigma_c,OFFSET_START,UProveParameters.QSIZE_BYTES);
		
	   	JBigInteger.add(parameters.sigma_c,OFFSET_START,UProveParameters.QSIZE_BYTES, parameters.beta1,OFFSET_START,UProveParameters.QSIZE_BYTES);
	 	if(jcMath.isGreater(parameters.sigma_c, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q, OFFSET_START,  UProveParameters.QSIZE_BYTES)>0)
	   	{
	   	   JBigInteger.subtract(parameters.sigma_c, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q, OFFSET_START,  UProveParameters.QSIZE_BYTES);
	   	}
	}
	
	public void generateThirdMessage()
	{
		
		Util.arrayCopy(parameters.sigma_c, IConsts.OFFSET_START, parameters.sigma_r,
				(short)(IConsts.OFFSET_START + Configuration.LENGTH_RSAOBJECT_MODULUS - UProveParameters.QSIZE_BYTES), UProveParameters.QSIZE_BYTES);
		
		jcMath.modMultiply(parameters.sigma_r, OFFSET_START, UProveParameters.PSIZE_BYTES,
				   parameters.y0,OFFSET_START,UProveParameters.QSIZE_BYTES,OFFSET_START); //TODO pad the input
		// sigma_r contains the sigma*c
		q.from_byte_array(Configuration.LENGTH_RSAOBJECT_MODULUS, (short) (Configuration.LENGTH_RSAOBJECT_MODULUS-UProveParameters.QSIZE_BYTES), parameters.q, IConsts.OFFSET_START);
		
		res.from_byte_array(Configuration.LENGTH_RSAOBJECT_MODULUS,OFFSET_START, parameters.sigma_r, IConsts.OFFSET_START);
		res.remainder_divide(q, el);
		
		Util.arrayCopy(res.as_byte_array(),(short) (Configuration.LENGTH_RSAOBJECT_MODULUS-UProveParameters.QSIZE_BYTES), parameters.temp_ram, OFFSET_START, UProveParameters.QSIZE_BYTES);
		
		JBigInteger.add(parameters.temp_ram, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.w, OFFSET_START, UProveParameters.QSIZE_BYTES);
		if(jcMath.isGreater(parameters.temp_ram, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q, OFFSET_START,  UProveParameters.QSIZE_BYTES)>0)
	   	{
	   	   JBigInteger.subtract(parameters.sigma_r, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q, OFFSET_START,  UProveParameters.QSIZE_BYTES);
	   	}
		Util.arrayCopy(parameters.temp_ram, OFFSET_START,parameters.sigma_r, OFFSET_START, UProveParameters.QSIZE_BYTES);
	}
	public void computeTokenId()
	{
		
		Util.arrayCopy(parameters.sigma_r, OFFSET_START, parameters.temp_ram, OFFSET_START, UProveParameters.QSIZE_BYTES);
		JBigInteger.add(parameters.temp_ram, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.beta2,OFFSET_START,UProveParameters.QSIZE_BYTES);
		if(jcMath.isGreater(parameters.temp_ram,OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q,OFFSET_START,UProveParameters.QSIZE_BYTES)>0)
		{
			JBigInteger.subtract(parameters.temp_ram, OFFSET_START, UProveParameters.QSIZE_BYTES,parameters.q,OFFSET_START,UProveParameters.QSIZE_BYTES);
		}
		Util.arrayCopy(parameters.temp_ram, OFFSET_START,parameters.sigma_r_prime, OFFSET_START, UProveParameters.QSIZE_BYTES);
		// stores in temp_data token_id
		short offset = 0 ;
		offset = setNumber((short) parameters.UID_P_LENGTH, parameters.UID_P,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) UProveParameters.PSIZE_BYTES, parameters.h,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) parameters.T1_LENGTH, parameters.TI,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) parameters.P1_LENGTH, parameters.PI,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) UProveParameters.PSIZE_BYTES, parameters.sigma_s_prime,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) UProveParameters.QSIZE_BYTES, parameters.sigma_c_prime,OFFSET_START, parameters.array,offset);
		offset = setNumber((short) UProveParameters.QSIZE_BYTES, parameters.sigma_r_prime,OFFSET_START, parameters.array,offset);
		
		// return T = tempArray[0 offset];
	}
	boolean verify()
	{
		// left temp ram  [0 PSIZE_BYTES]
		Util.arrayCopy(parameters.sigma_a_prime, OFFSET_START, parameters.temp_ram, OFFSET_START, UProveParameters.PSIZE_BYTES);
		jcMath.modMultiply(parameters.temp_ram, OFFSET_START, UProveParameters.PSIZE_BYTES,
				   parameters.sigma_b_prime,OFFSET_START,UProveParameters.PSIZE_BYTES,OFFSET_START); // don't write to disk because costs too match
		
		
		Util.arrayCopy(parameters.g, OFFSET_START, parameters.temp_ram, UProveParameters.PSIZE_BYTES, UProveParameters.PSIZE_BYTES);
		jcMath.modMultiply(parameters.temp_ram, UProveParameters.PSIZE_BYTES, UProveParameters.PSIZE_BYTES,
				   parameters.h,OFFSET_START,UProveParameters.PSIZE_BYTES,OFFSET_START);
		
		byte[] result = jcMath.modPow(parameters.temp_ram, UProveParameters.PSIZE_BYTES, UProveParameters.PSIZE_BYTES,
			parameters.sigma_r_prime, OFFSET_START, UProveParameters.QSIZE_BYTES);
		
		Util.arrayCopy(result, Configuration.TEMP_OFFSET_RSA,parameters.temp_ram, UProveParameters.PSIZE_BYTES, UProveParameters.PSIZE_BYTES);
															// in [PSIZE_BYTES PSIZE_BYTES] first operand
		
		Util.arrayCopy(parameters.g_i[0].value, OFFSET_START, parameters.temp_ram, (short) (2*UProveParameters.PSIZE_BYTES), UProveParameters.PSIZE_BYTES);
		jcMath.modMultiply(parameters.temp_ram, (short) (2*UProveParameters.PSIZE_BYTES), UProveParameters.PSIZE_BYTES,
				   parameters.sigma_s_prime,OFFSET_START,UProveParameters.PSIZE_BYTES,OFFSET_START);
		
		
		byte[] resultFull = jcMath.modPowFull(parameters.temp_ram, (short) (2*UProveParameters.PSIZE_BYTES), UProveParameters.PSIZE_BYTES,
				parameters.p_minus_two,OFFSET_START,(short) UProveParameters.PSIZE_BYTES);
		
		result = jcMath.modPow(resultFull, OFFSET_START, UProveParameters.PSIZE_BYTES,
				parameters.sigma_c_prime, OFFSET_START,UProveParameters.QSIZE_BYTES);
		
		Util.arrayCopy(result,Configuration.TEMP_OFFSET_RSA,parameters.temp_ram, (short) (2*UProveParameters.PSIZE_BYTES), UProveParameters.PSIZE_BYTES);
		
		jcMath.modMultiply(parameters.temp_ram, (short) (2*UProveParameters.PSIZE_BYTES), UProveParameters.PSIZE_BYTES,
				parameters.temp_ram,(short)UProveParameters.PSIZE_BYTES,UProveParameters.PSIZE_BYTES,OFFSET_START);
		
		Util.arrayCompare(parameters.temp_ram, (short) (2*UProveParameters.PSIZE_BYTES), parameters.temp_ram, OFFSET_START, UProveParameters.PSIZE_BYTES);
		//Util.arrayCompare(parameters.temp_ram, (short) (UProveParameters.PSIZE_BYTES), parameters.temp_ram, OFFSET_START, UProveParameters.PSIZE_BYTES);
		return true;
	}
	
}
