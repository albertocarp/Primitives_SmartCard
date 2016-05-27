package sid;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import sid.Sha3Keccak.double_uint8;

public class Sha3Keccak160 extends Sha3Keccak
{

	static Sha3Keccak160 p_Instance = null;
	
	public Sha3Keccak160()
	{
		this.KECCAK_VALUE_W = 8;
		KECCAK_STATE_SIZE_BITS = (short) (25*KECCAK_VALUE_W);
		KECCAK_CAPACITY = (short) (2*KECCAK_SEC_LEVEL);
		KECCAK_RATE = (short) (KECCAK_STATE_SIZE_BITS - KECCAK_CAPACITY);
		KECCAK_STATE_SIZE_WORDS  = (short) ((short)(KECCAK_STATE_SIZE_BITS+ (short)((short)(PROCESSOR_WORD-1)))/(PROCESSOR_WORD));
		KECCAK_RATE_SIZE_WORDS =  (short) ((short)(KECCAK_RATE+(short)(PROCESSOR_WORD-1))/(PROCESSOR_WORD));
		state = new double_uint8[KECCAK_STATE_SIZE_WORDS];
		KECCAK_NUMBER_OF_ROUNDS = 18;
		KECCAK_SIZE_BYTES = 20;
		
	}
	public void postInit()
	{
		for ( short i = 0 ; i < KECCAK_STATE_SIZE_WORDS;i++)
			state[i] = new double_uint8();
		for ( short i = 0 ; i < 3;i++)
			sC[i] = new double_uint8();
		for ( short i = 0 ; i < 15;i++)
			sB[i] = new double_uint8();
	}
	void keccak_rot1(double_uint8 word_src_uint8,double_uint8 word_dest)
	{
	    short word_src = Util.makeShort(word_src_uint8.msb,word_src_uint8.lsb);
	    short out = (short) (((short)( word_src << 1 ) & (short)0xFEFF) | (( (short)((word_src & (short)0x8080) >>> 7)) & (short)0x0101));
	    word_dest.lsb = (byte)(out & 0xff);
	    word_dest.msb = (byte)( ((short)(out >>> 8) & 0x00FF) & 0xff);
	}
	
	byte keccak_rot(byte word_src_s,byte noRotations)
	{
		noRotations =  (byte) (noRotations & 0x07);
		short ret = (short)(word_src_s >>> (8 - noRotations));
		byte test = 0x00;
		if((short)(8-noRotations) == 1)
			test = (byte) (ret & (short)0x007f);
		if((short)(8-noRotations) == 2)
			test = (byte) (ret & (short)0x003f);
		if((short)(8-noRotations) == 3)
			test = (byte) (ret & (short)0x001f);
		if((short)(8-noRotations) == 4)
			test = (byte) (ret & (short)0x000f);
		if((short)(8-noRotations) == 5)
			test = (byte) (ret & (short)0x0007);
		if((short)(8-noRotations) == 6)
			test = (byte) (ret & (short)0x0003);
		if((short)(8-noRotations) == 7)
			test = (byte) (ret & (short)0x0001);
		if((short)(8-noRotations) == 8)
			test = (byte) (ret & (short)0x0000);
		byte word_dest =   (byte) ((( word_src_s << noRotations )) | test);
		return word_dest;
	}
	
	byte keccak_rc(byte word,byte i)
	{
		switch(i)
		{
			case 0:
				word ^= 0x01;
				break;
			case 1:
				word ^= 0x82;
				break;
			case 2:
				word ^= 0x8A;
				break;
			case 4:
				word ^= 0x8B;
				break;
			case 5:
				word ^= 0x01;
				break;
			case 6:
				word ^= 0x81;
				break;
			case 7:
				word ^= 0x09;
				break;
			case 8:
				word ^= 0x8A;
				break;
			case 9:
				word ^= 0x88;
				break;
			case 10:
				word ^= 0x09;
				break;
			case 11:
				word ^= 0x0A;
				break;
			case 12:
				word ^= 0x8B;
				break;
			case 13:
				word ^= 0x8B;
				break;
			case 14:
				word ^= 0x89;
				break;
			case 15:
				word ^= 0x03;
				break;
			case 16:
				word ^= 0x02;
				break;
			case 17:
				word ^= 0x80;
				break;
			case 18:
				word ^= 0x0A;
				break;
			case 19:
				word ^= 0x0A;
				break;
		}
		return word;
	}

	void keccak_function_f(double_uint8[] state)
	{
		byte i=0;
		state_extra_bytes1.lsb = state[2].msb;
		state_extra_bytes1.msb = state[3].lsb;
		state[3].lsb = state[3].msb;
		state[3].msb = state[4].lsb;
		state[4].lsb = state[4].msb;

		state_extra_bytes2.lsb = state[7].msb;
		state_extra_bytes2.msb = state[8].lsb;
		state[8].lsb = state[8].msb;
		state[8].msb = state[9].lsb;
		state[9].lsb = state[9].msb;
		
	for(; i < KECCAK_NUMBER_OF_ROUNDS; i++){
			
			/* ms
				step theta
			*/
			sC[0].msb = (byte) (state[0].msb ^ state_extra_bytes1.msb ^ state[5].msb ^ state_extra_bytes2.msb ^ state[10].msb);
			sC[0].lsb = (byte) (state[0].lsb ^ state_extra_bytes1.lsb ^ state[5].lsb ^ state_extra_bytes2.lsb ^ state[10].lsb);
			
			sC[1].msb = (byte) (state[1].msb ^ state[3].msb  ^ state[6].msb ^ state[8].msb   ^ state[11].msb);
			sC[1].lsb = (byte) (state[1].lsb ^ state[3].lsb  ^ state[6].lsb ^ state[8].lsb   ^ state[11].lsb);
			
			sC[2].msb = (byte) (state[2].msb ^ state[4].msb           ^ state[7].msb ^ state[9].msb           ^ state[12].msb);
			sC[2].lsb = (byte) (state[2].lsb ^ state[4].lsb           ^ state[7].lsb ^ state[9].lsb           ^ state[12].lsb);
			
			keccak_rot1(sC[0], sB[0]);
			keccak_rot1(sC[1], sB[1]);
			keccak_rot1(sC[2], sB[2]);
		
			temp.lsb = sB[0].msb;
			temp.msb = sB[1].lsb;
			
			sC[2].msb = sC[0].lsb;
			
			temp.msb ^= sC[2].msb;
			temp.lsb ^= sC[2].lsb;
			
			state[0].msb             ^=  temp.msb;
			state[0].lsb             ^=  temp.lsb;
			
			
			state_extra_bytes1.msb   ^=  temp.msb;
			state_extra_bytes1.lsb   ^=  temp.lsb;	
			state[5].msb           ^=  temp.msb;
			state[5].lsb           ^=  temp.lsb;
			
			state_extra_bytes2.msb ^=  temp.msb;
			state_extra_bytes2.lsb ^=  temp.lsb;
			state[10].msb          ^=  temp.msb;
			state[10].lsb          ^=  temp.lsb;
			sC[0].lsb = sC[0].msb;
			sC[0].msb = sC[1].lsb;
			temp.lsb  = sB[1].msb;
			temp.msb  = sB[2].lsb;
			
			temp.msb ^= sC[0].msb;
			temp.lsb ^= sC[0].lsb;
			state[1].msb           ^=  temp.msb;
			state[1].lsb           ^=  temp.lsb;
			state[3].msb           ^=  temp.msb;
			state[3].lsb           ^=  temp.lsb;
			state[6].msb           ^=  temp.msb;
			state[6].lsb           ^=  temp.lsb;
			state[8].msb           ^=  temp.msb;
			state[8].lsb           ^=  temp.lsb;
			state[11].msb          ^=  temp.msb;
			state[11].lsb          ^=  temp.lsb;
			

			sC[1].lsb = sC[1].msb;

			temp.msb = (byte) (sC[1].msb ^ sB[0].msb);
			temp.lsb = (byte) (sC[1].lsb ^ sB[0].lsb);
			
			state[2].msb	         ^=  temp.msb;
			state[2].lsb	         ^=  temp.lsb;
			
			state[4].msb	         ^=  temp.msb;
			state[4].lsb	         ^=  temp.lsb;
			
			state[7].msb	         ^=  temp.msb;
			state[7].lsb	         ^=  temp.lsb;
			
			state[9].msb	         ^=  temp.msb;
			state[9].lsb	         ^=  temp.lsb;
			
			state[12].msb	         ^=  temp.msb;
			state[12].lsb	         ^=  temp.lsb;
		
			/* 
				step rho and pi 
			*/
			 sB[0].lsb = keccak_rot(state[0].lsb, (byte) 0);
			 sB[6].lsb = keccak_rot(state[0].msb, (byte) 1);
			 sB[12].lsb = keccak_rot(state[1].lsb, (byte) 62);
			 sB[3].lsb = keccak_rot(state[1].msb, (byte) 28);
			 sB[9].lsb = keccak_rot(state[2].lsb, (byte) 27);
			
			 sB[9].msb = keccak_rot(state_extra_bytes1.lsb, (byte) 36);
			 sB[0].msb = keccak_rot(state_extra_bytes1.msb, (byte) 44);
			 sB[6].msb = keccak_rot(state[3].lsb, (byte) 6);
			 sB[12].msb = keccak_rot(state[3].msb, (byte) 55);
			 sB[3].msb = keccak_rot(state[4].lsb, (byte) 20);
			 sB[4].lsb = keccak_rot(state[5].lsb, (byte) 3);
			 sB[10].lsb = keccak_rot(state[5].msb, (byte) 10);
			
			
			 sB[1].lsb  = keccak_rot(state[6].lsb, (byte) 43);
			 sB[7].lsb  = keccak_rot(state[6].msb, (byte) 25);
			 sB[13].lsb = keccak_rot(state[7].lsb, (byte) 39);
			 sB[13].msb = keccak_rot(state_extra_bytes2.lsb,  (byte) 41);
			 sB[4].msb = keccak_rot(state_extra_bytes2.msb, (byte) 45);
			 sB[10].msb = keccak_rot(state[8].lsb, (byte) 15);
			 sB[1].msb = keccak_rot(state[8].msb, (byte) 21);
			 sB[7].msb = keccak_rot(state[9].lsb, (byte) 8);
			 sB[8].lsb = keccak_rot(state[10].lsb, (byte) 18);
			 sB[14].lsb = keccak_rot(state[10].msb, (byte) 2);
			 sB[5].lsb = keccak_rot(state[11].lsb,(byte) 61);
			 sB[11].lsb = keccak_rot(state[11].msb,(byte) 56);
			 sB[2].lsb = keccak_rot(state[12].lsb, (byte) 14);
								 
			/* 
				step chi 
			*/
			temp.lsb = sB[0].msb;
			temp.msb = sB[1].lsb;
			state[0].msb = (byte) (sB[0].msb ^ ((~ temp.msb) & sB[1].msb));
			state[0].lsb = (byte) (sB[0].lsb ^ ((~ temp.lsb) & sB[1].lsb));
			
			temp.lsb = sB[1].msb;
			temp.msb = sB[2].lsb;
			sB[2].msb = sB[0].lsb;
			state[1].msb = (byte) (sB[1].msb ^ ((~ temp.msb) & sB[2].msb));
			state[1].lsb = (byte) (sB[1].lsb ^ ((~ temp.lsb) & sB[2].lsb));
			
			temp.lsb = sB[0].msb;
			state[2].msb = (byte) (sB[2].msb ^ ((~ sB[0].msb) & temp.msb));
			state[2].lsb = (byte) (sB[2].lsb ^ ((~ sB[0].lsb) & temp.lsb));

			temp.lsb = sB[3].msb;
			temp.msb = sB[4].lsb;
			state_extra_bytes1.msb = (byte) (sB[3].msb ^ ((~ temp.msb) & sB[4].msb));
			state_extra_bytes1.lsb = (byte) (sB[3].lsb ^ ((~ temp.lsb) & sB[4].lsb));
			
			temp.lsb = sB[4].msb;
			temp.msb = sB[5].lsb;
			sB[5].msb = sB[3].lsb;
			state[3].msb = (byte) (sB[4].msb ^ ((~ temp.msb) & sB[5].msb));
			state[3].lsb = (byte) (sB[4].lsb ^ ((~ temp.lsb) & sB[5].lsb));
			
			temp.lsb = sB[3].msb;
			state[4].msb = (byte) (sB[5].msb ^ ((~ sB[3].msb) & temp.msb));
			state[4].lsb = (byte) (sB[5].lsb ^ ((~ sB[3].lsb) & temp.lsb));

			temp.lsb = sB[6].msb;
			temp.msb = sB[7].lsb;
			state[5].msb = (byte) (sB[6].msb ^ ((~ temp.msb) & sB[7].msb));
			state[5].lsb = (byte) (sB[6].lsb ^ ((~ temp.lsb) & sB[7].lsb));
			
			temp.lsb = sB[7].msb;
			temp.msb = sB[8].lsb;
			
			sB[8].msb = sB[6].lsb;
			state[6].msb = (byte) (sB[7].msb ^ ((~ temp.msb) & sB[8].msb));
			state[6].lsb = (byte) (sB[7].lsb ^ ((~ temp.lsb) & sB[8].lsb));
			
			temp.lsb = sB[6].msb;
			state[7].msb = (byte) (sB[8].msb ^ ((~ sB[6].msb) & temp.msb));
			state[7].lsb = (byte) (sB[8].lsb ^ ((~ sB[6].lsb) & temp.lsb));

			temp.lsb = sB[9].msb;
			temp.msb = sB[10].lsb;
			state_extra_bytes2.msb = (byte) (sB[9].msb ^ ((~ temp.msb) & sB[10].msb));
			state_extra_bytes2.lsb = (byte) (sB[9].lsb ^ ((~ temp.lsb) & sB[10].lsb));
			
			temp.lsb = sB[10].msb;
			temp.msb = sB[11].lsb;
			sB[11].msb = sB[9].lsb;		
			state[8].msb = (byte) (sB[10].msb ^ ((~ temp.msb) & sB[11].msb));
			state[8].lsb = (byte) (sB[10].lsb ^ ((~ temp.lsb) & sB[11].lsb));
			
			temp.lsb = sB[9].msb;		
			state[9].msb = (byte) (sB[11].msb ^ ((~ sB[9].msb) & temp.msb));
			state[9].lsb = (byte) (sB[11].lsb ^ ((~ sB[9].lsb) & temp.lsb));

			temp.lsb = sB[12].msb;
			temp.msb = sB[13].lsb;
			state[10].msb = (byte) (sB[12].msb ^ ((~ temp.msb) & sB[13].msb));
			state[10].lsb = (byte) (sB[12].lsb ^ ((~ temp.lsb) & sB[13].lsb));
			
			temp.lsb = sB[13].msb;
			temp.msb = sB[14].lsb;
			sB[14].msb = sB[12].lsb;		
			state[11].msb = (byte) (sB[13].msb ^ ((~ temp.msb) & sB[14].msb));
			state[11].lsb = (byte) (sB[13].lsb ^ ((~ temp.lsb) & sB[14].lsb));

			temp.lsb = sB[12].msb;				
			state[12].msb = (byte) (sB[14].msb ^ ((~ sB[12].msb) & temp.msb));
			state[12].lsb = (byte) (sB[14].lsb ^ ((~ sB[12].lsb) & temp.lsb));

			/* 
				step iota 
			*/
			state[0].lsb = keccak_rc(state[0].lsb, i);
		}

		/* The state needs to be reformatted in the most compressed way to be usefull */

		state[4].msb = state[4].lsb;
		state[4].lsb = state[3].msb;
		state[3].msb = state[3].lsb;
		state[3].lsb = state_extra_bytes1.msb; 
		state[2].msb = state_extra_bytes1.lsb; 

		state[9].msb = state[9].lsb;
		state[9].lsb = state[8].msb;
		state[8].msb = state[8].lsb;
		state[8].lsb = state_extra_bytes2.msb; 
		state[7].msb = state_extra_bytes2.lsb; 
	}

	void keccak_sponge_init(keccack_state_internal state)
	{
		state.state_control = 0x00;
		state.squeezing_mode = 0x00;
		//Util.arrayFillNonAtomic(state.state, (short)0x00, (short)(16 * KECCAK_STATE_SIZE_WORDS), (byte)0x00);
	}
	void keccak_sponge_absorb(keccack_state_internal state,byte[] message,short message_size_bytes)
	{
		byte state_address;
		short message_address;
		message_address = 0;
		state_address = state.state_control;
		if(state_address >= 128){
			state_address -=128;
			state.state[state_address].msb ^= message[message_address];
			message_size_bytes--;
			message_address++;	
			state_address++;
		}
		for(; (state_address != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (message_size_bytes > 1); state_address++){
			temp.lsb = message[message_address];
			temp.msb = message[(short)(message_address+1)];
			state.state[state_address].msb ^= temp.msb;
			state.state[state_address].lsb ^= temp.lsb;
			message_size_bytes-=2;
			message_address+=2;
		}
		if((state_address == (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (message_size_bytes != 0)){
			temp.lsb = message[message_address];
			temp.msb = 0;
			state.state[state_address].msb ^= temp.msb;
			state.state[state_address].lsb ^= temp.lsb;
			message_size_bytes--;
			message_address++;
			state_address++;
		}
		if((state_address != KECCAK_RATE_SIZE_WORDS) && (message_size_bytes == 1)){
			state.state[state_address].lsb ^= message[message_address];
			message_size_bytes--;
			message_address++;	
			state_address+=128; /* Most significative bit used to indicate if the world is absorbed by half */
		}
		while(message_size_bytes > 1){
			keccak_function_f(state.state);
			for(state_address = 0; (state_address != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (message_size_bytes > 1); state_address++)
			{
				temp.lsb = message[message_address];
				temp.msb = message[(short)(message_address+1)];
				state.state[state_address].msb ^= temp.msb;
				state.state[state_address].lsb ^= temp.lsb;
				message_size_bytes-=2;
				message_address+=2;
			}
			if((state_address == (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (message_size_bytes != 0)){
				temp.lsb = message[message_address];
				temp.msb = 0;
				state.state[state_address].msb ^= temp.msb;
				state.state[state_address].lsb ^= temp.lsb;
				message_size_bytes--;
				message_address++;
				state_address++;
			}
			if(message_size_bytes == 1)
			{
				if((state_address == KECCAK_RATE_SIZE_WORDS)){
					keccak_function_f(state.state);
					state_address = 0;
				}
				state.state[state_address].lsb ^= message[message_address];
				message_size_bytes--;
				message_address++;	
				state_address+=128; /* Most significative bit used to indicate if the world is absorbed by half */
			}
		}
			if(state_address == KECCAK_RATE_SIZE_WORDS)
			{
				state.state_control = 0;
				keccak_function_f(state.state);
			}
			else{
				state.state_control = state_address;
			}
	}

	void keccak_sponge_squeeze(keccack_state_internal state, byte[] output, short output_size_bytes)
	{
		byte state_address;
		short output_address;	
		if(state.squeezing_mode == 0){
			if(state.state_control >= 128){
				state.state_control-=128; /* Most significative bit used to indicate if the world is absorbed by half */
				state.state[state.state_control].msb ^= 0x01;
				state.state[state.state_control].lsb ^= 0x00;
			}
			else{
				state.state[state.state_control].msb ^= 0x00;	
				state.state[state.state_control].lsb ^= 0x01;
			}
			state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
			state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
			
			keccak_function_f(state.state);
			state.state_control = 0;
			state.squeezing_mode = 1;
		}
		output_address = 0;
		state_address = state.state_control;
		if(state_address >= 128){
			state_address -=128;		
			output[output_address] = state.state[state_address].msb;
			output_size_bytes--;	
			output_address++;
			state_address++;
		}
		for(; (state_address != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (output_size_bytes > 1); state_address++){
			output[output_address] = state.state[state_address].lsb;
			output[(short)(output_address+1)] = state.state[state_address].msb;
			output_size_bytes-=2;	
			output_address+=2;
		}
		if((state_address == (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (output_size_bytes != 0)){
			output[output_address] = state.state[state_address].lsb;
			output_size_bytes--;	
			output_address++;
			state_address++;
		}
		if((state_address != KECCAK_RATE_SIZE_WORDS) && (output_size_bytes == 1)){
			output[output_address] = state.state[state_address].lsb;
			output_size_bytes--;	
			output_address++;
			state_address +=128;
		}
		while(output_size_bytes > 1){
			keccak_function_f(state.state);
			for(state_address = 0; (state_address != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (output_size_bytes > 1); state_address++){
				output[output_address] = state.state[state_address].lsb;
				output[(short)(output_address+1)] = state.state[state_address].msb;
				output_size_bytes-=2;	
				output_address+=2;
			}
			if((state_address == (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (output_size_bytes != 0)){
				output[output_address] = state.state[state_address].lsb;
				output_size_bytes--;	
				output_address++;
				state_address++;
			}
		}
		if(output_size_bytes == 1){
			if((state_address == KECCAK_RATE_SIZE_WORDS)){
				keccak_function_f(state.state);
				state_address = 0;
			}
			output[output_address] = state.state[state_address].lsb;
			output_size_bytes--;	
			output_address++;
			state_address +=128;
		}
		if(state_address == KECCAK_RATE_SIZE_WORDS){
			state.state_control = 0;
			keccak_function_f(state.state);
		}
		else{
			state.state_control = state_address;
		}
	}
	
	void keccak_duplex_init(keccack_state_internal state)
	{
		
	}
	
	void keccak_duplex_duplexing(keccack_state_internal  state, byte[]  message, byte message_size_bytes,  byte[] duplex, byte duplex_size_bytes)
	{
		
		byte x, message_base_address;
		message_base_address = 0;
		if (duplex_size_bytes > (short)(KECCAK_RATE/8)){
			duplex_size_bytes = (byte) (KECCAK_RATE/8);
		}
		if (message_size_bytes > (short)(KECCAK_RATE/8)){
			/* No Padding */
			for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS-1)); x++){
				temp.lsb = message[message_base_address];
				temp.msb = message[(short)(message_base_address+1)];
				state.state[x].lsb ^= temp.lsb;
				state.state[x].msb ^= temp.msb;
				message_size_bytes-=2;
				message_base_address+=2;
			}
			temp.lsb = message[message_base_address];
			temp.msb = 0;
			state.state[x].msb ^= temp.msb;
			state.state[x].lsb ^= temp.lsb;
			message_size_bytes--;
			message_base_address++;
			x++;
		}
		else
		{
			message_size_bytes++; /*  Padding */
			for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (message_size_bytes > 2); x++){
				temp.lsb = message[message_base_address];
				temp.msb = message[(short)(message_base_address+1)];
				state.state[x].msb ^= temp.msb;
				state.state[x].lsb ^= temp.lsb;
				message_size_bytes-=2;
				message_base_address+=2;		
			}
			if(x == (short)(KECCAK_RATE_SIZE_WORDS - 1)){
				if(message_size_bytes == 1){
					state.state[x].lsb ^= 0x01;
					state.state[x].msb ^= 0x00;
					state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
					state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
				}
				else{
					temp.lsb = message[message_base_address];
					temp.msb = 0;
					state.state[x].msb ^= temp.msb;
					state.state[x].lsb ^= temp.lsb;
				}
				message_size_bytes--;	
				message_base_address++;	
			}
			else if(message_size_bytes == 2){
					temp.lsb = message[message_base_address];
					temp.msb = 1;
					state.state[x].msb ^= temp.msb;
					state.state[x].lsb ^= temp.lsb;
					state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
					state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
					message_size_bytes-=2;
					message_base_address+=2;
			}
			else if(message_size_bytes == 1){
					state.state[x].msb ^= 0x00;
					state.state[x].lsb ^= 0x01;
					state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
					state.state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
					message_size_bytes--;
					message_base_address++;
			}
			else{
					temp.lsb = message[message_base_address];
					temp.msb = message[message_base_address+1];
					state.state[x].msb ^= temp.msb;
					state.state[x].lsb ^= temp.lsb;
					message_size_bytes-=2;
					message_base_address+=2;
			}
		}
		keccak_function_f(state.state);
		message_base_address=0;
		for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (duplex_size_bytes > 1); x++){
			duplex[message_base_address] = state.state[x].lsb;
			duplex[(short)(message_base_address+1)] = state.state[x].msb;
			duplex_size_bytes-=2;
			message_base_address+=2;
		}
		if(duplex_size_bytes >= 1)
		{
			duplex[message_base_address] = state.state[x].lsb;
		}
	}

	void keccak_hash(byte[] message, short message_size_bytes, byte[]  hash, short hash_size_bytes)
	{
		hash_size_bytes = KECCAK_SIZE_BYTES;
		short message_base_address;
		byte x;
		short size = (short) ((KECCAK_STATE_SIZE_WORDS - KECCAK_RATE_SIZE_WORDS+1)*2);
		short offset = (short)(KECCAK_RATE_SIZE_WORDS-1);
		for ( short j = offset; j < (short)(size/2);j++)
		{
			state[j].lsb = 0x00;
			state[j].msb = 0x00;
		}
		if(message_size_bytes >= (short)(KECCAK_RATE/8)){
		    for ( short j = 0 ; j < (short)(KECCAK_RATE/8);j+=2)
		    {
		    	state[j].lsb = message[j];
				state[j].msb = message[(short)(j+1)];
		    }
			message_size_bytes -= (short)((short)(KECCAK_RATE/8) - 1);
			message_base_address = (short) (KECCAK_RATE/8);
		}
		else
		{
			  for ( short j = 0 ; j < (short)(message_size_bytes);j+=2)
			    {
			    	state[j].lsb = message[j];
					state[j].msb = message[(short)(j+1)];
			    }
			  x = (byte)(message_size_bytes >> 1);
			  if((message_size_bytes & 1) == 0){
					state[x].lsb = 1;
					state[x].msb = 0;
				}
				else{
					state[x].msb = 1;		
				}
				x++;
				size = (short) (((KECCAK_RATE_SIZE_WORDS - x))*2);
				for ( short j = x ; j < (short)(size/2);j++)
			    {
			    	state[j].lsb = 0x00;
					state[j].msb = 0x00;
			    }
				state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
				state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
				message_base_address = message_size_bytes;
				message_size_bytes = 0;	
		}
		keccak_function_f(state);
		while(message_size_bytes != 0)
		{
			for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (message_size_bytes > 2); x++){
				temp.lsb = message[message_base_address];
				temp.msb = message[(short)(message_base_address+1)];
				state[x].msb ^= temp.msb;
				state[x].lsb ^= temp.lsb;
				message_size_bytes-=2;
				message_base_address+=2;
			}
			if(x == (short)(KECCAK_RATE_SIZE_WORDS - 1)){
				if(message_size_bytes == 1){
					state[x].msb ^= 0x00;
					state[x].lsb ^= 0x01;
					state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
					state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
				}
				else{
					temp.lsb = message[message_base_address];
					temp.msb = 0;
					state[x].msb ^= temp.msb;
					state[x].lsb ^= temp.lsb;
				}
				message_size_bytes--;	
				message_base_address++;	
			}
			else if(message_size_bytes == 2){
					temp.lsb = message[message_base_address];
					temp.msb = 0x01;
					state[x].msb ^= temp.msb;
					state[x].lsb ^= temp.lsb;
					state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
					state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
					message_size_bytes-=2;
					message_base_address+=2;
			}
			else if(message_size_bytes == 1){
					state[x].msb ^= 0x00;
					state[x].lsb ^= 0x01;
					state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb ^= 0x00;
					state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb ^= 0x80;
					message_size_bytes--;
					message_base_address++;
			}
			else{
					temp.lsb = message[message_base_address];
					temp.msb = message[(short)(message_base_address+1)];
					state[x].msb ^= temp.msb;
					state[x].lsb ^= temp.lsb;
					message_size_bytes-=2;
					message_base_address+=2;
			}
			keccak_function_f(state);
	   }
		message_base_address = 0;
		for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (hash_size_bytes > 1); x++){
			hash[message_base_address] = state[x].lsb;
			hash[(short)(message_base_address+1)] = state[x].msb;
			hash_size_bytes-=2;
			message_base_address+=2;
		}
		if(hash_size_bytes >= 1){
				hash[message_base_address] = state[x].lsb;
				hash_size_bytes--;
				message_base_address++;
				x++;
		}
		while((hash_size_bytes != 0)){
			keccak_function_f(state);
			for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (hash_size_bytes > 1); x++){
				hash[message_base_address] = state[x].lsb;
				hash[(short)(message_base_address+1)] = state[x].msb;
				hash_size_bytes-=2;
				message_base_address+=2;
			}
			if(hash_size_bytes >= 1){
				hash[message_base_address] = state[x].lsb;
				hash_size_bytes--;
				message_base_address++;
				x++;
			}
		}
	}
	
	public static Sha3Keccak160 getInstance()
	{
		if(p_Instance == null)
			p_Instance = new Sha3Keccak160();
		return p_Instance;
	}
	
	
	
}
