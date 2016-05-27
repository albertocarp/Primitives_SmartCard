package sid;

import sid.Sha3Keccak.double_uint8;

public class Sha3Keccak_r128_c272 extends Sha3Keccak_W16
{
	static Sha3Keccak_r128_c272 p_Instance = null;
	
	public void postInit() {
		sC = new double_uint8[5];
		sB = new double_uint8[25];
		for ( short i = 0 ; i < KECCAK_STATE_SIZE_WORDS;i++)
			state[i] = new double_uint8();
		for ( short i = 0 ; i < 5;i++)
			sC[i] = new double_uint8();
		for ( short i = 0 ; i < 25;i++)
			sB[i] = new double_uint8();
		
	}
	private Sha3Keccak_r128_c272()
	{
		this.KECCAK_VALUE_W = 16;
		KECCAK_SEC_LEVEL = 136;
		KECCAK_STATE_SIZE_BITS = (short) (25*KECCAK_VALUE_W);
		KECCAK_CAPACITY = (short) (2*KECCAK_SEC_LEVEL);
		KECCAK_RATE = (short) (KECCAK_STATE_SIZE_BITS - KECCAK_CAPACITY);
		KECCAK_STATE_SIZE_WORDS  = (short) ((short)(KECCAK_STATE_SIZE_BITS+ (short)((short)(PROCESSOR_WORD-1)))/(PROCESSOR_WORD));
		KECCAK_RATE_SIZE_WORDS =  (short) ((short)(KECCAK_RATE+(short)(PROCESSOR_WORD-1))/(PROCESSOR_WORD));
		state = new double_uint8[KECCAK_STATE_SIZE_WORDS];
		KECCAK_NUMBER_OF_ROUNDS = 20;
		KECCAK_SIZE_BYTES = 34;
	}
	
	public static Sha3Keccak_r128_c272 getInstance()
	{
		if(p_Instance == null)
			p_Instance = new Sha3Keccak_r128_c272();
		return p_Instance;
	}
}
