package sid;

import javacard.framework.Util;
import sid.Sha3Keccak.double_uint8;

public abstract class Sha3Keccak_W16 extends Sha3Keccak {

	double_uint8 temp  = new double_uint8();
	double_uint8 temp2  = new double_uint8();

		
	void keccak_rot1(double_uint8 word_src_uint8,double_uint8 word_dest)
	{
		word_dest.value = (short) ((word_src_uint8.value << 1) |
				((short)(word_src_uint8.value >>> (16 - 1)) & (short)0x0001));
	}
	public abstract void postInit();

	double_uint8 keccak_rot(double_uint8 word_src,byte rotations)
	{
		rotations = (byte) (rotations & 0x0F); /* rotations mod 16 */
		short ret_rotations = (short)(16 - rotations);
		short first = (short)(word_src.value << rotations);
		short last  = (short)(word_src.value >>> ((short)16 - rotations));
		if(ret_rotations == 1)
			last =  (short) (last & (short)0x7fff);
		if(ret_rotations == 2)
			last = (short) (last & (short)0x3fff);
		if(ret_rotations == 3)
			last = (short) (last & (short)0x1fff);
		if(ret_rotations == 4)
			last = (short) (last & (short)0x0fff);
		if(ret_rotations == 5)
			last = (short) (last & (short)0x07ff);
		if(ret_rotations == 6)
			last = (short) (last & (short)0x03ff);
		if(ret_rotations == 7)
			last = (short) (last & (short)0x01ff);
		if(ret_rotations == 8)
			last = (short) (last & (short)0x00ff);
		if(ret_rotations == 9)
			last = (short) (last & (short)0x007f);
		if(ret_rotations == 10)
			last = (short) (last & (short)0x003f);
		if(ret_rotations == 11)
			last = (short) (last & (short)0x001f);
		if(ret_rotations == 12)
			last = (short) (last & (short)0x000f);
		if(ret_rotations == 13)
			last = (short) (last & (short)0x0007);
		if(ret_rotations == 14)
			last = (short) (last & (short)0x0003);
		if(ret_rotations == 15)
			last = (short) (last & (short)0x0001);
		if(ret_rotations == 16)
			last = (short) (last & (short)0x0000);
		temp2.value = (short) ( last | first);
		return temp2;
	}
	double_uint8 keccak_rc(double_uint8 word,byte i)
	{
		switch(i)
		{
		case 0:
			word.value ^= 0x0001;
			break;
		case 1:
			word.value ^= (short)0x8082;
			break;
		case 2:
			word.value ^= (short)0x808A;
			break;
		case 3:
			word.value ^= (short)0x8000;
			break;
		case 4:
			word.value ^= (short)0x808B;
			break;
		case 5:
			word.value ^= (short)0x0001;
			break;
		case 6:
			word.value ^= (short)0x8081;
			break;
		case 7:
			word.value ^= (short)0x8009;
			break;
		case 8:
			word.value ^= (short)0x008A;
			break;
		case 9:
			word.value ^= (short)0x0088;
			break;
		case 10:
			word.value ^= (short)0x8009;
			break;
		case 11:
			word.value ^= (short)0x000A;
			break;
		case 12:
			word.value ^= (short)0x808B;
			break;
		case 13:
			word.value ^= (short)0x008B;
			break;
		case 14:
			word.value ^= (short)0x8089;
			break;
		case 15:
			word.value ^= (short)0x8003;
			break;
		case 16:
			word.value ^= (short)0x8002;
			break;
		case 17:
			word.value ^= (short)0x0080;
			break;
		case 18:
			word.value ^= (short)0x800A;
			break;
		case 19:
			word.value ^= (short)0x000A;
			break;
		}
		return word;
	}
	
	void keccak_function_f(double_uint8[] state)
	{
		short i=0;
		for(; i < KECCAK_NUMBER_OF_ROUNDS; i++){
			
	
			sC[0].value = (short) (state[0].value ^ state[5].value ^ state[10].value ^ state[15].value ^ state[20].value);
			sC[1].value = (short) (state[1].value ^ state[6].value ^ state[11].value ^ state[16].value ^ state[21].value);
			sC[2].value = (short) (state[2].value ^ state[7].value ^ state[12].value ^ state[17].value ^ state[22].value);
			sC[3].value = (short) (state[3].value ^ state[8].value ^ state[13].value ^ state[18].value ^ state[23].value);
			sC[4].value = (short) (state[4].value ^ state[9].value ^ state[14].value ^ state[19].value ^ state[24].value);
				
			keccak_rot1(sC[0], sB[0]);
			keccak_rot1(sC[1], sB[1]);
			keccak_rot1(sC[2], sB[2]);
			keccak_rot1(sC[3], sB[3]);
			keccak_rot1(sC[4], sB[4]);
		
			temp.value = (short) (sC[4].value ^ sB[1].value);
			state[0].value  ^= temp.value;
			state[5].value  ^= temp.value;
			state[10].value ^= temp.value;
			state[15].value ^= temp.value;
			state[20].value ^= temp.value;
			temp.value = (short) (sC[0].value ^ sB[2].value);
			state[1].value  ^= temp.value;
			state[6].value  ^= temp.value;
			state[11].value ^= temp.value;
			state[16].value ^= temp.value;
			state[21].value ^= temp.value;
			temp.value = (short) (sC[1].value ^ sB[3].value);
			state[2].value  ^= temp.value;
			state[7].value  ^= temp.value;
			state[12].value ^= temp.value;
			state[17].value ^= temp.value;
			state[22].value ^= temp.value;
			temp.value = (short) (sC[2].value ^ sB[4].value);
			state[3].value  ^= temp.value;
			state[8].value  ^= temp.value;
			state[13].value ^= temp.value;
			state[18].value ^= temp.value;
			state[23].value ^= temp.value;
			temp.value = (short) (sC[3].value ^ sB[0].value);
			state[4].value  ^= temp.value;
			state[9].value  ^= temp.value;
			state[14].value ^= temp.value;
			state[19].value ^= temp.value;
			state[24].value ^= temp.value;

			/*
				step rho and pi
			*/
			sB[0].value  = keccak_rot(state[0], (byte) 0).value;
			sB[10].value = keccak_rot(state[1], (byte) 1).value;
			sB[20].value = keccak_rot(state[2], (byte) 62).value;
			sB[5].value  = keccak_rot(state[3], (byte) 28).value;
			sB[15].value = keccak_rot(state[4], (byte) 27).value;
			sB[16].value = keccak_rot(state[5], (byte) 36).value;
			sB[1].value  = keccak_rot(state[6], (byte) 44).value;
			sB[11].value = keccak_rot(state[7], (byte) 6).value;
			sB[21].value = keccak_rot(state[8], (byte) 55).value;
			
			sB[6].value  = keccak_rot(state[9],(byte) 20).value;
			sB[7].value  = keccak_rot(state[10],(byte) 3).value;
			sB[17].value = keccak_rot(state[11],(byte) 10).value;
			
			sB[2].value  = keccak_rot(state[12], (byte) 43).value;
			sB[12].value = keccak_rot(state[13], (byte) 25).value;
			sB[22].value = keccak_rot(state[14], (byte) 39).value;
			sB[23].value = keccak_rot(state[15], (byte) 41).value;
			sB[8].value  = keccak_rot(state[16], (byte) 45).value;
			
			sB[18].value = keccak_rot(state[17], (byte) 15).value;
			sB[3].value =  keccak_rot(state[18],  (byte) 21).value;
			sB[13].value = keccak_rot(state[19], (byte) 8).value;
			sB[14].value = keccak_rot(state[20],  (byte) 18).value;
			
			sB[24].value= keccak_rot(state[21], (byte) 2).value;
			sB[9].value = keccak_rot(state[22], (byte) 61).value;
			sB[19].value = keccak_rot(state[23],(byte) 56).value;
			sB[4].value = keccak_rot(state[24] ,  (byte) 14).value;
			
			/*
				step chi
			*/
			state[0].value = (short) (sB[0].value ^ ((~ sB[1].value) & sB[2].value));
			state[1].value = (short) (sB[1].value ^ ((~ sB[2].value) & sB[3].value));
			state[2].value = (short) (sB[2].value ^ ((~ sB[3].value) & sB[4].value));
			state[3].value = (short) (sB[3].value ^ ((~ sB[4].value) & sB[0].value));
			state[4].value = (short) (sB[4].value ^ ((~ sB[0].value) & sB[1].value));

			state[5].value = (short) (sB[5].value ^ ((~ sB[6].value) & sB[7].value));
			state[6].value = (short) (sB[6].value ^ ((~ sB[7].value) & sB[8].value));
			state[7].value = (short) (sB[7].value ^ ((~ sB[8].value) & sB[9].value));
			state[8].value = (short) (sB[8].value ^ ((~ sB[9].value) & sB[5].value));
			state[9].value = (short) (sB[9].value ^ ((~ sB[5].value) & sB[6].value));

			state[10].value = (short) (sB[10].value ^ ((~ sB[11].value) & sB[12].value));
			state[11].value = (short) (sB[11].value ^ ((~ sB[12].value) & sB[13].value));
			state[12].value = (short) (sB[12].value ^ ((~ sB[13].value) & sB[14].value));
			state[13].value = (short) (sB[13].value ^ ((~ sB[14].value) & sB[10].value));
			state[14].value = (short) (sB[14].value ^ ((~ sB[10].value) & sB[11].value));

			state[15].value = (short) (sB[15].value ^ ((~ sB[16].value) & sB[17].value));
			state[16].value = (short) (sB[16].value ^ ((~ sB[17].value) & sB[18].value));
			state[17].value = (short) (sB[17].value ^ ((~ sB[18].value) & sB[19].value));
			state[18].value = (short) (sB[18].value ^ ((~ sB[19].value) & sB[15].value));
			state[19].value = (short) (sB[19].value ^ ((~ sB[15].value) & sB[16].value));

			state[20].value = (short) (sB[20].value ^ ((~ sB[21].value) & sB[22].value));
			state[21].value = (short) (sB[21].value ^ ((~ sB[22].value) & sB[23].value));
			state[22].value = (short) (sB[22].value ^ ((~ sB[23].value) & sB[24].value));
			state[23].value = (short) (sB[23].value ^ ((~ sB[24].value) & sB[20].value));
			state[24].value = (short) (sB[24].value ^ ((~ sB[20].value) & sB[21].value));

			state[0]= keccak_rc(state[0], (byte) i);
		}
	}
	void keccak_hash(byte[] message, short message_size_bytes, byte[] hash, short hash_size_bytes) {
		hash_size_bytes = KECCAK_SIZE_BYTES;
		short message_base_address;
		byte x;
		short size = (short) ((KECCAK_STATE_SIZE_WORDS - KECCAK_RATE_SIZE_WORDS+1)*2);
		short offset = (short)(KECCAK_RATE_SIZE_WORDS-1);
		for ( short j = offset; j < (short)(size/2);j++)
		{
			state[j].value = 0x00;
			state[j].msb = 0x00;
			state[j].lsb = 0x00;
		}
		if(message_size_bytes >= (short)(KECCAK_RATE/8)){
		    for ( short j = 0 ; j < (short)(KECCAK_RATE/8);j+=2)
		    {
		    	
		    	state[j].lsb = message[j];
				state[j].msb = message[(short)(j+1)];
				state[j].value = Util.makeShort(state[j].msb , state[j].lsb);
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
					state[j].value = Util.makeShort(state[j].msb , state[j].lsb);
			    }
			  x = (byte)(message_size_bytes >> 1);
			  if((message_size_bytes & 1) == 0){
					state[x].lsb = 1;
					state[x].msb = 0;
					state[x].value = Util.makeShort(state[x].msb , state[x].lsb);
				}
				else{
					state[x].msb = 1;		
					state[x].value = Util.makeShort(state[x].msb , state[x].lsb);
				}
				x++;
				size = (short) (((KECCAK_RATE_SIZE_WORDS - x))*2);
				for ( short j = x ; j < (short)(size/2);j++)
			    {
					state[j].value = 0x00;
					state[j].msb = 0x00;
					state[j].lsb = 0x00;
			    }
				state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].value ^= (short)0x8000;
				state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].msb  ^= 0x80;
				state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].lsb  ^= 0x00;
				message_base_address = message_size_bytes;
				message_size_bytes = 0;	
		}
		keccak_function_f(state);
		while(message_size_bytes != 0){
			for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (message_size_bytes > 2); x++){
				temp.lsb = message[message_base_address];
				temp.msb = message[(short)(message_base_address+1)];
				temp.value = Util.makeShort(temp.msb, temp.lsb);
				state[x].value ^= temp.value;
				message_size_bytes-=2;
				message_base_address+=2;
			}
			if(message_size_bytes == 2){
				temp.lsb = message[message_base_address];
				temp.msb = 0x01;
				temp.value = Util.makeShort(temp.msb, temp.lsb);
				state[x].value ^= temp.value;
				state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].value ^= (short)0x8000;
				message_size_bytes-=2;
				message_base_address+=2;
			
			}
			else if(message_size_bytes == 1){
				state[x].value ^= 1;
				state[(short)(KECCAK_RATE_SIZE_WORDS - 1)].value ^= (short)0x8000;
				message_size_bytes--;
				message_base_address++;
			}
			else{
				temp.lsb = message[message_base_address];
				temp.msb = message[(short)(message_base_address+1)];
				temp.value = Util.makeShort(temp.msb, temp.lsb);
				state[x].value ^= temp.value;
				message_size_bytes-=2;
				message_base_address+=2;
			}
			keccak_function_f(state);
		}
		message_base_address = 0;
		for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (hash_size_bytes > 1); x++){
			state[x].lsb = (byte)state[x].value;
			state[x].msb = (byte)((short)(state[x].value >>> 8) & (short)0x00ff);
			hash[message_base_address] = state[x].lsb;
			hash[(short)(message_base_address+1)] = state[x].msb;
			temp.value = Util.makeShort(temp.msb, temp.lsb);
			hash_size_bytes-=2;
			message_base_address+=2;
		}
		if(hash_size_bytes >= 1){
			state[x].lsb = (byte)state[x].value;
			state[x].msb = (byte)((short)(state[x].value >>> 8) & 0x00ff);
			if(hash_size_bytes == 1){
				hash[message_base_address] = state[x].lsb;
				hash_size_bytes--;
				message_base_address++;
			}
			else{
				hash[message_base_address] = state[x].lsb;
				hash[(short)(message_base_address+1)] = state[x].msb;
				hash_size_bytes-=2;
				message_base_address+=2;
			}
			x++;
		}
		while((hash_size_bytes != 0)){	
			keccak_function_f(state);
			for(x = 0; (x != (short)(KECCAK_RATE_SIZE_WORDS - 1)) && (hash_size_bytes > 1); x++){
				state[x].lsb = (byte)state[x].value;
				state[x].msb = (byte)((short)(state[x].value >>> 8) & 0x00ff);
				hash[message_base_address] = state[x].lsb;
				hash[(short)(message_base_address+1)] = state[x].msb;
				hash_size_bytes-=2;
				message_base_address+=2;
			}
			if(hash_size_bytes >= 1){
				state[x].lsb = (byte)state[x].value;
				state[x].msb = (byte)((short)(state[x].value >>> 8) & 0x00ff);
				if(hash_size_bytes == 1){
					hash[message_base_address] = state[x].lsb;
					hash_size_bytes--;
					message_base_address++;
				}
				else{
					hash[message_base_address] = state[x].lsb;
					hash[(short)(message_base_address+1)] = state[x].msb;
					hash_size_bytes-=2;
					message_base_address+=2;
				}
				x++;
			}
		}
	}
	


}
