package sid;

import sid.Sha3Keccak.double_uint8;

public class Sha3Keccak_r256c544 extends Sha3Keccak_W32{
	
static Sha3Keccak_r256c544 p_Instance = null;
	
	public void postInit() {
		
		sC = new double_uint8[(short)(5*(KECCAK_VALUE_W/16))];
		sB = new double_uint8[(short)(25*(KECCAK_VALUE_W/16))];
		for ( short i = 0 ; i < KECCAK_STATE_SIZE_WORDS;i++)
			state[i] = new double_uint8();
		for ( short i = 0 ; i < (short)(5*(KECCAK_VALUE_W/16));i++)
			sC[i] = new double_uint8();
		for ( short i = 0 ; i < (short)(25*(KECCAK_VALUE_W/16));i++)
			sB[i] = new double_uint8();
	}
	private Sha3Keccak_r256c544()
	{
		KECCAK_VALUE_W = 32;
		KECCAK_SEC_LEVEL = 272;
		KECCAK_STATE_SIZE_BITS = (short) (25*KECCAK_VALUE_W);
		KECCAK_CAPACITY = (short) (2*KECCAK_SEC_LEVEL);
		KECCAK_RATE = (short) (KECCAK_STATE_SIZE_BITS - KECCAK_CAPACITY);
		KECCAK_STATE_SIZE_WORDS  = (short) ((short)(KECCAK_STATE_SIZE_BITS+ (short)((short)(PROCESSOR_WORD-1)))/(PROCESSOR_WORD));
		KECCAK_RATE_SIZE_WORDS =  (short) ((short)(KECCAK_RATE+(short)(PROCESSOR_WORD-1))/(PROCESSOR_WORD));
		state = new double_uint8[KECCAK_STATE_SIZE_WORDS];
		KECCAK_NUMBER_OF_ROUNDS = 22;
		KECCAK_SIZE_BYTES = 544/8;
	}
	public static Sha3Keccak_r256c544 getInstance()
	{
		if(p_Instance == null)
			p_Instance = new Sha3Keccak_r256c544();
		return p_Instance;
	}
}
