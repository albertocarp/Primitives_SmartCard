package sid;

public interface IConsts 
{
	/**
	 * System variables
	 */
	public static final byte  UNTOUCHED_VALUE = 0x02;
	public static final byte  TRUE = 0x01;
	public static final byte  FALSE = 0x03;
	public static final byte  OFFSET_START=0x00;
	public static final short INVALID_DATA_LENGTH=-1;
	
	/**
	 * CMD_CLA variables
	 */
	public static final byte OFFSET_CLA_APPLICATION = (byte) 0x00;
	
	public static final byte OFFSET_INS_LIGHT =  (byte) 0x11;
	public static final byte OFFSET_INS_SYSTEM = (byte) 0x21;
	public static final byte OFFSET_INS_UPROVE = (byte) 0x22;
	public static final byte OFFSET_INS_TEST   = (byte) 0x23; 
	public static final byte OFFSET_INS_HASH   = (byte) 0x24;

	public static final byte OFFSET_P1_ENC 	 = (byte) 0x21;
	public static final byte OFFSET_P1_DEC	 = (byte) 0x22;
	public static final byte OFFSET_P1_GEN 	 = (byte) 0x23;
	
	
	
	/***
	 * For Lightweight cryptography
	 */
	public static final byte TWINE_CIPHER_80=0x30;
	public static final byte TWINE_CIPHER_128=0x31;
	public static final byte LBLOCK_CIPHER=0x32;
	public static final byte ZORRO_CIPHER=0x33;
	public static final byte PICOLLO_CIPHER=0x34;
	public static final byte RECTANGLE_CIPHER=0x35;
	
	
	/**
	 * For U Prove cipher
	 */
	public static final byte CMD_SET_E_I = 0x50;
	public static final byte CMD_GET_E_I = 0x51;
	
	public static final byte CMD_SET_PUB_KEY = 0x52;
	public static final byte CMD_GET_PUB_KEY = 0x53;
	
	public static final byte CMD_SET_UIDP = 0x54;
	public static final byte CMD_GET_UIDP = 0x55;
	
	public static final byte CMD_GET_PQG = 0x56;
	public static final byte CMD_SET_PQG = 0x57;
	
	public static final byte CMD_GET_UIDH = 0x58;
	public static final byte CMD_SET_UIDH = 0x59;
	
	public static final byte CMD_GET_ATTR_COUNT = 0x60;
	public static final byte CMD_SET_ATTR_COUNT = 0x49;
	
	public static final byte CMD_GET_ATTR_VAL   = 0x61;
	public static final byte CMD_SET_ATTR_VAL   = 0x62;
	
	public static final byte CMD_SET_ATTR_VAL_PUBLIC =0x63;
	
	public static final byte CMD_PRECOMPUTE_INPUTS = 0x64;
	public static final byte CMD_SET_TI =0x65;
	public static final byte CMD_GET_TI =0x66;
	public static final byte CMD_SET_PI=0x67;
	public static final byte CMD_GET_PI=0x68;
	
	public static final byte CMD_GET_GAMMA = 0x69;
	public static final byte CMD_TEST_FIRST_MESSAGE=0x70;
	public static final byte CMD_TEST_SECOND_MESSAGE=0x71;
	public static final byte CMD_TEST_THIRD_MESSAGE=0x72;
	
	public static final byte HASH_KECCAK_160  = 0x40;
	public static final byte HASH_KECCAK_r144c256  = 0x41;
	public static final byte HASH_KECCAK_r128c272 = 0x42;
	public static final byte HASH_KECCAK_r544c256 = 0x43;
	public static final byte HASH_KECCAK_r512c288 = 0x44;
	public static final byte HASH_KECCAK_r256c544 = 0x46;
	
	
	public static final byte HASH = 0x00;
	
	
	/**
	 *  for test mode
	 */
	public static final byte CMD_TEST_LOOP_INC=(byte) 0x00;
	public static final byte CMD_TEST_LOOP_DEC=(byte) 0x01;
	
	public static final byte CMD_TEST_READ_EEPROM_EEPROM = 0x03;
	public static final byte CMD_TEST_WRITE_EEPROM_EEPROM=0x04;
	
	public static final byte CMD_TEST_READ_RAM_DESELECT=0x05;
	public static final byte CMD_TEST_WRITE_RAM_DESELECT=0x06;
	
	public static final byte CMD_TEST_READ_RAM_RESET=0x07;
	public static final byte CMD_TEST_WRITE_RAM_RESET=0x08;
	
	public static final byte CMD_READ_EEPROM_WRITE_RAM=0x09;
	public static final byte CMD_READ_RAM_WRITE_EEPROM=0x10;
	
	public static final byte CMD_ADD_BIG=0x11;
	public static final byte CMD_MOD_POW_RAM=0x12;
	public static final byte CMD_MOD_POW_EEPROM=0x13;
	
	public static final byte CMD_MOD_MULL_RAM=0x14;
	public static final byte CMD_MOD_MULL_EEPROM=0x15; 
	
	public static final byte CMD_TEST_MEMORY=0x16;
	public static final byte CMD_FULL_TEST_DEBUG=0x17;
	
}
