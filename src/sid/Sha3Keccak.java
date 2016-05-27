package sid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import sid.Sha3Keccak.double_uint8;

public abstract class Sha3Keccak implements IConsts 
{
	protected short KECCAK_VALUE_W;
	protected short KECCAK_STATE_SIZE_BITS;
	protected short KECCAK_NUMBER_OF_ROUNDS;
	protected short KECCAK_SEC_LEVEL = 80;
	protected short PROCESSOR_WORD = 16;
	protected short KECCAK_CAPACITY;
	protected short KECCAK_RATE;
	protected short KECCAK_STATE_SIZE_WORDS;
	protected short KECCAK_RATE_SIZE_WORDS;
	protected short KECCAK_SIZE_BYTES;
	protected short TEMPORARY_MEMORY=128;
	protected byte[] transientMemory = JCSystem.makeTransientByteArray(TEMPORARY_MEMORY, JCSystem.CLEAR_ON_DESELECT);
	protected byte[] transientHash = JCSystem.makeTransientByteArray(TEMPORARY_MEMORY, JCSystem.CLEAR_ON_DESELECT);
	protected byte OFFSET_MESSAGE=0x00;
	protected double_uint8 sC[] = new double_uint8[3];
	protected double_uint8 sB[] = new double_uint8[15];
	protected double_uint8 temp = new double_uint8();
	protected double_uint8 state_extra_bytes1 = new double_uint8();
	protected double_uint8 state_extra_bytes2 = new double_uint8();
	protected double_uint8 temp2 = new double_uint8();
	protected double_uint8[] state;
	
	public class keccack_state_internal {
		public double_uint8[] state = new double_uint8[KECCAK_RATE_SIZE_WORDS]; 
		public byte state_control;
		public byte squeezing_mode;
	};
	
	public class double_uint8{
		public byte msb;
		public byte lsb;
		public short value;
	};
	protected keccack_state_internal keccak_state;
	
	abstract void keccak_hash(byte[] message,short message_size,byte[] hash,short hash_size);
	
	public abstract void postInit();
	
	public static Sha3Keccak getInstance(final byte cipher)
	{
		switch(cipher)
		{
			case IConsts.HASH_KECCAK_160:
				return Sha3Keccak160.getInstance();
			case IConsts.HASH_KECCAK_r144c256:
				return Sha3Keccak_r144_c256.getInstance();
			case IConsts.HASH_KECCAK_r128c272:
				return Sha3Keccak_r128_c272.getInstance();
			case IConsts.HASH_KECCAK_r544c256:
				return Sha3Keccak_r544_c256.getInstance();
			case IConsts.HASH_KECCAK_r512c288:
				return Sha3Keccak_r512c288.getInstance();
			case IConsts.HASH_KECCAK_r256c544:
				return Sha3Keccak_r512c288.getInstance();
				
		}
		ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);;
		return null;
	}
	
	public short process(byte type,byte[] message,byte message_offset,short message_size)
	{
		Util.arrayCopy(message, message_offset, transientMemory, OFFSET_MESSAGE, message_size);
		keccak_hash(transientMemory,message_size,transientHash,KECCAK_SIZE_BYTES);
		Util.arrayCopy(transientHash,OFFSET_MESSAGE, message, (short) message_offset, KECCAK_SIZE_BYTES);
		return KECCAK_SIZE_BYTES;
		
	}
	
}
