package sid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class TestCase {

	private static final short LENGTH_DATA=128;
	private static final short LENGTH_DATA_SMALL=20;
	private static final short OFFSET_START=0;
	private JCMath jcMath;
	private static TestCase m_Instance=null;
	private byte[] ram_reset1;
	private byte[] ram_reset2;
	private byte[] ram_deselect1;
	private byte[] ram_deselect2;
	private byte[] eeProm1;
	private byte[] eeProm2;
	private TestCase() {
		
		ram_reset1 = JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_RESET);
		ram_deselect1 =  JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_DESELECT);
		eeProm1 = new byte[LENGTH_DATA];
		ram_reset2 = JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_RESET);
		ram_deselect2 =  JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_DESELECT);
		eeProm2 = new byte[LENGTH_DATA];
		jcMath.updateModulus(TestUProve.GROUP_P,OFFSET_START,UProveParameters.PSIZE_BYTES);
	}
	public static  TestCase getInstance()
	{
		if(m_Instance == null)
			m_Instance = new TestCase();
		return m_Instance;
	}
	public void runInc()
	{
		byte[] p = TestUProve.GROUP_P;
		short p_length = 16000;
		short p_it=0;
		short x=0;
		for (;p_it != p_length;p_it++)
		{
			x = 0;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 1;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 2;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 3;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 4;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 5;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 6;
		}
		for (;p_it != p_length;p_it++)
		{
			x = 7;
		}
	}
	public void runDec()
	{
		byte[] p = TestUProve.GROUP_P;
		short p_length = 16000;
		short p_it=p_length;
		short x=0;
		for (;p_it != 0;--p_it)
		{
			x = 0;
		}
		for (;p_it != 0;--p_it)
		{
			x = 1;
		}
		for (;p_it != 0;--p_it)
		{
			x = 2;
		}
		for (;p_it != 0;--p_it)
		{
			x = 3;
		}
		for (;p_it != 0;--p_it)
		{
			x = 4;
		}
		for (;p_it != 0;--p_it)
		{
			x = 5;
		}
		for (;p_it != 0;--p_it)
		{
			x = 6;
		}
		for (;p_it != 0;--p_it)
		{
			x = 7;
		}
		
	}
	public void testWriteRamRamDeselect()
	{
		RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM).generateData(ram_deselect1,OFFSET_START,LENGTH_DATA);
		Util.arrayCopy(ram_deselect1,OFFSET_START,ram_deselect2,OFFSET_START, LENGTH_DATA);
	}
	public void testWriteRamRamReset()
	{
		RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM).generateData(ram_reset1,OFFSET_START,LENGTH_DATA);
		Util.arrayCopy(ram_reset1,OFFSET_START,ram_reset2,OFFSET_START, LENGTH_DATA);
	}
	public void testAdditionBig()
	{
		Util.arrayCopy(TestUProve.GROUP_P,OFFSET_START,ram_reset1,OFFSET_START, LENGTH_DATA);
		Util.arrayCopy(TestUProve.GROUP_G,OFFSET_START,ram_reset2,OFFSET_START, LENGTH_DATA);
		JBigInteger.add(ram_reset1,OFFSET_START,UProveParameters.PSIZE_BYTES,ram_reset2,OFFSET_START,UProveParameters.PSIZE_BYTES);
	}
	public void testModPowRam()
	{
		Util.arrayCopy(TestUProve.GROUP_G,OFFSET_START,ram_reset1,OFFSET_START, LENGTH_DATA);
		Util.arrayCopy(TestUProve.GROUP_Q,OFFSET_START,ram_reset2,OFFSET_START, LENGTH_DATA_SMALL);
		jcMath.modPow(ram_reset1, OFFSET_START, LENGTH_DATA, ram_reset2, OFFSET_START, LENGTH_DATA_SMALL);
		jcMath.updateModulus(TestUProve.GROUP_P,OFFSET_START,UProveParameters.PSIZE_BYTES);
	}
	public void testModPowEeprom()
	{
		Util.arrayCopy(TestUProve.GROUP_G,OFFSET_START,eeProm1,OFFSET_START, LENGTH_DATA);
		Util.arrayCopy(TestUProve.GROUP_Q,OFFSET_START,eeProm2,OFFSET_START, LENGTH_DATA_SMALL);
		jcMath.modPow(eeProm1, OFFSET_START, LENGTH_DATA, eeProm2, OFFSET_START, LENGTH_DATA_SMALL);
		jcMath.updateModulus(TestUProve.GROUP_P,OFFSET_START,UProveParameters.PSIZE_BYTES);
	}
	public void testModMullEEprom()
	{
		Util.arrayCopy(TestUProve.GROUP_G,OFFSET_START,eeProm1,OFFSET_START, LENGTH_DATA);
		Util.arrayCopy(TestUProve.GROUP_G,OFFSET_START,eeProm2,OFFSET_START, LENGTH_DATA);

		//jcMath.modMultiply(eeProm1, OFFSET_START, LENGTH_DATA, eeProm2, OFFSET_START, LENGTH_DATA,OFFSET_START);
		jcMath.updateModulus(TestUProve.GROUP_P,OFFSET_START,UProveParameters.PSIZE_BYTES);
	}
	public void testModMullRam()
	{
		Util.arrayCopy(TestUProve.GROUP_G,OFFSET_START,ram_reset1,OFFSET_START, LENGTH_DATA);
		Util.arrayCopy(TestUProve.GROUP_G,OFFSET_START,ram_reset2,OFFSET_START, LENGTH_DATA);

	//	jcMath.modMultiply(ram_reset1, OFFSET_START, LENGTH_DATA, ram_reset2, OFFSET_START, LENGTH_DATA,OFFSET_START);
		jcMath.updateModulus(TestUProve.GROUP_P,OFFSET_START,UProveParameters.PSIZE_BYTES);
	}
	public void testMemory()
	{
		ram_reset1 = JCSystem.makeTransientByteArray(LENGTH_DATA,JCSystem.CLEAR_ON_RESET);
	}
	public byte[] testMul()
	{
		byte[] test = new byte[128];
		Util.arrayFillNonAtomic(test, OFFSET_START,UProveParameters.PSIZE_BYTES,(byte)0x00);
		test[127]=0x12;
		test[126]=0x13;
		test[125]=0x14;
		byte[] test2 = new byte[128];
		Util.arrayFillNonAtomic(test2, OFFSET_START,UProveParameters.PSIZE_BYTES,(byte)0x00);
		test2[127]=0x11;
		test2[126]=0x12;
		test2[125]=0x13;
		jcMath.test_mode=true;
		return null;
		
	}
	
}
