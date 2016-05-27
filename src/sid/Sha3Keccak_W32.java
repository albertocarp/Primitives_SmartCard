package sid;

import javacard.framework.Util;
import sid.Sha3Keccak.double_uint8;

public abstract class Sha3Keccak_W32 extends Sha3Keccak 
{
	double_uint8 temp  = new double_uint8();
	
	void keccak_rot1(double_uint8[] word_src_uint8,double_uint8[] word_dest,short offset_src,short offset_dst)
	{
		short temp;
		temp = word_src_uint8[offset_src].value;
		word_dest[offset_dst].value = (short) ((word_src_uint8[offset_src].value << 1) |
				((word_src_uint8[(short)(offset_src+1)].value >>> (16 - 1) & (short)0x0001))); 
		word_dest[(short)(offset_dst + 1)].value = (short) ((word_src_uint8[(short)(offset_src+1)].value << 1) 
				| ((temp >>> (16 - 1) & (short)0x0001))); 
	}
	void keccak_rot(double_uint8[] word_src,double_uint8 word_dst[],byte rotations,short offset,short offset_dest)
	{
		short temp;
		rotations = (byte) (rotations & 0x1F);
		if(rotations >= 16){
			temp = word_src[offset].value;
			word_dst[offset_dest].value = word_src[(short)(offset+1)].value;
			word_dst[(short)(offset_dest+1)].value = temp;
			rotations -= 16;
			word_src[offset].value = word_dst[offset_dest].value;
			word_src[(short)(offset+1)].value = word_dst[(short)(offset_dest+1)].value;
		}
		temp = word_src[offset].value;
		short ret_rotations = (short)(16 - rotations);
		short last = (short) (word_src[(short)(offset+1)].value >>> ((short)(16 - rotations)));
		short last2 = (short) (temp >>> ((short)(16 - rotations)));
		if(ret_rotations == 1)
		{
			last =  (short) (last & (short)0x7fff);
			last2 =  (short) (last2 & (short)0x7fff);
		}
		if(ret_rotations == 2)
		{
			last = (short) (last & (short)0x3fff);
			last2 = (short) (last2 & (short)0x3fff);
		}
		if(ret_rotations == 3)
		{
			last = (short) (last & (short)0x1fff);
			last2 = (short) (last2 & (short)0x1fff);
		}
		if(ret_rotations == 4)
		{
			last = (short) (last & (short)0x0fff);
			last2 = (short) (last2 & (short)0x0fff);
		}
		if(ret_rotations == 5)
		{
			last = (short) (last & (short)0x07ff);
			last2 = (short) (last2 & (short)0x07ff);
		}
		if(ret_rotations == 6)
		{
			last = (short) (last & (short)0x03ff);
			last2 = (short) (last2 & (short)0x03ff);
		}
		if(ret_rotations == 7)
		{
			last = (short) (last & (short)0x01ff);
			last2 = (short) (last2 & (short)0x01ff);
		}
		if(ret_rotations == 8)
		{
			last = (short) (last & (short)0x00ff);
			last2 = (short) (last2 & (short)0x00ff);
		}
		if(ret_rotations == 9)
		{
			last = (short) (last & (short)0x007f);
			last2 = (short) (last2 & (short)0x007f);
		}
		if(ret_rotations == 10)
		{
			last = (short) (last & (short)0x003f);
			last2 = (short) (last2 & (short)0x003f);
		}
		if(ret_rotations == 11)
		{
			last = (short) (last & (short)0x001f);
			last2 = (short) (last2 & (short)0x001f);
		}
		if(ret_rotations == 12)
		{
			last = (short) (last & (short)0x000f);
			last2 = (short) (last2 & (short)0x000f);
		}
		if(ret_rotations == 13)
		{
			last = (short) (last & (short)0x0007);
			last2 = (short) (last2 & (short)0x0007);
		}
		if(ret_rotations == 14)
		{
			last = (short) (last & (short)0x0003);
			last2 = (short) (last2 & (short)0x0003);
		}
		if(ret_rotations == 15)
		{
			last = (short) (last & (short)0x0001);
			last2 = (short) (last2 & (short)0x0001);
		}
		if(ret_rotations == 16)
		{
			last = (short) (last & (short)0x0000);
			last2 = (short) (last2 & (short)0x0000);
		}
		word_dst[offset_dest].value = (short) ((word_src[offset].value << rotations) | last ); 
		word_dst[(short)(offset_dest+1)].value = (short) ((word_src[(short)(offset+1)].value << rotations) |  last2); 
	}
	
	void keccak_rc(double_uint8 word[],byte i)
	{
		switch(i)
		{
			case 0:
				word[0].value ^= 0x0001;
				break;
			case 1:
				word[0].value ^= (short)(0x8082);
				break;
			case 2:
				word[0].value ^= (short)0x808A;
				break;
			case 3:
				word[0].value ^= (short)0x8000;
				word[1].value ^= (short)0x8000;
				break;
			case 4:
				word[0].value ^= (short)0x808B;
				break;
			case 5:
				word[0].value ^= 0x0001;
				word[1].value ^= (short) 0x8000;
				break;
			case 6:
				word[0].value ^= (short)0x8081;
				word[1].value ^= (short)0x8000;
				break;
			case 7:
				word[0].value ^=(short) 0x8009;
				break;
			case 8:
				word[0].value ^= (short)0x008A;
				break;
			case 9:
				word[0].value ^= 0x0088;
				break;
			case 10:
				word[0].value ^= (short)0x8009;
				word[1].value ^= (short)0x8000;
				break;
			case 11:
				word[0].value ^= (short)0x000A;
				word[1].value ^= (short)0x8000;
				break;
			case 12:
				word[0].value ^= (short)0x808B;
				word[1].value ^= (short)0x8000;
				break;
			case 13:
				word[0].value ^= 0x008B;
				break;
			case 14:
				word[0].value ^= (short)0x8089;
				break;
			case 15:
				word[0].value ^= (short)0x8003;
				break;
			case 16:
				word[0].value ^= (short)0x8002;
				break;
			case 17:
				word[0].value ^= 0x0080;
				break;
			case 18:
				word[0].value ^= (short)0x800A;
				break;
			case 19:
				word[0].value ^= 0x000A;
				word[1].value ^= (short)0x8000;
				break;
			case 20:
				word[0].value ^= (short)0x8081;
				word[1].value ^= (short)0x8000;
				break;
			case 21:
				word[0].value ^= (short)0x8080;
				break;	
				
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
	
	public abstract void postInit();
	
	void keccak_function_f(double_uint8[] state)
	{
		short j, x, y,i=0;
		for(; i < KECCAK_NUMBER_OF_ROUNDS; i++){
			
			/*
				step theta
			*/
			for(x = 0; x != (short)(5*(short)(KECCAK_VALUE_W/16)); x++){
				sC[x].value = (short) (state[x].value ^ state[(short)(x + 5*(short)(KECCAK_VALUE_W/16))].value ^ state[(short)(x + 10*(KECCAK_VALUE_W/16))].value ^ 
						state[(short)(x + (short)15*((short)KECCAK_VALUE_W/16))].value ^ state[(short)(x + (short)20*((short)KECCAK_VALUE_W/16))].value);
			}

			for(x = 0; x != (short)(5*(KECCAK_VALUE_W/16)); x+=(KECCAK_VALUE_W/16)){
				keccak_rot1(sC, sB,x,x);
			}
		
			for(j = 0; j != (short)(KECCAK_VALUE_W/16); j++){
				temp.value = (short) (sC[(short)((4*(KECCAK_VALUE_W/16)) + j)].value ^ sB[(short)((1*(KECCAK_VALUE_W/16)) + j)].value);
				state[(short)((0*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((5*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((10*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((15*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((20*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				temp.value = (short) (sC[(short)((0*(KECCAK_VALUE_W/16)) + j)].value ^ sB[(short)((2*(KECCAK_VALUE_W/16)) + j)].value);
				state[(short)((1*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((6*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((11*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((16*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((21*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				temp.value = (short) (sC[(short)((1*(KECCAK_VALUE_W/16)) + j)].value ^ sB[(short)((3*(KECCAK_VALUE_W/16)) + j)].value);
				state[(short)((2*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((7*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((12*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((17*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((22*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				temp.value = (short) (sC[(short)((2*(KECCAK_VALUE_W/16)) + j)].value ^ sB[(short)((4*(KECCAK_VALUE_W/16)) + j)].value);
				state[(short)((3*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((8*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((13*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((18*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((23*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				temp.value = (short) (sC[(short)((3*(KECCAK_VALUE_W/16)) + j)].value ^ sB[(short)((0*(KECCAK_VALUE_W/16)) + j)].value);
				state[(short)((4*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((9*(KECCAK_VALUE_W/16)) + j)].value     ^=  temp.value;
				state[(short)((14*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((19*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
				state[(short)((24*(KECCAK_VALUE_W/16)) + j)].value    ^=  temp.value;
			}
		
			/*
				step rho and pi
			*/
			keccak_rot(state, sB, (byte)0,(short)(0),(short)0);
			keccak_rot(state, sB, (byte)1,(short)(KECCAK_VALUE_W/16),(short)((short)(10*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)62,(short)((short)(2*KECCAK_VALUE_W)/16),(short)((short)(20*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)28,(short)((short)(3*KECCAK_VALUE_W)/16),(short)((short)(5*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)27,(short)((short)(4*KECCAK_VALUE_W)/16),(short)((short)(15*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)36,(short)((short)(5*KECCAK_VALUE_W)/16),(short)((short)(16*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)44,(short)((short)(6*KECCAK_VALUE_W)/16),(short)((short)(1*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)6,(short)((short)(7*KECCAK_VALUE_W)/16),(short)((short)(11*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)55,(short)((short)(8*KECCAK_VALUE_W)/16),(short)((short)(21*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)20,(short)((short)(9*KECCAK_VALUE_W)/16),(short)((short)(6*KECCAK_VALUE_W)/16));
			
			keccak_rot(state, sB, (byte)3,(short)((short)(10*KECCAK_VALUE_W)/16),(short)((short)(7*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)10,(short)((short)(11*KECCAK_VALUE_W)/16),(short)((short)(17*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)43,(short)((short)(12*KECCAK_VALUE_W)/16),(short)((short)(2*KECCAK_VALUE_W)/16));
			
			
			keccak_rot(state, sB, (byte)25,(short)((short)(13*KECCAK_VALUE_W)/16),(short)((short)(12*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)39,(short)((short)(14*KECCAK_VALUE_W)/16),(short)((short)(22*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)41,(short)((short)(15*KECCAK_VALUE_W)/16),(short)((short)(23*KECCAK_VALUE_W)/16));
		
			keccak_rot(state, sB, (byte)45,(short)((short)(16*KECCAK_VALUE_W)/16),(short)((short)(8*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)15,(short)((short)(17*KECCAK_VALUE_W)/16),(short)((short)(18*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)21,(short)((short)(18*KECCAK_VALUE_W)/16),(short)((short)(3*KECCAK_VALUE_W)/16));
			
			keccak_rot(state, sB, (byte)8,(short)((short)(19*KECCAK_VALUE_W)/16),(short)((short)(13*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)18,(short)((short)(20*KECCAK_VALUE_W)/16),(short)((short)(14*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)2,(short)((short)(21*KECCAK_VALUE_W)/16),(short)((short)(24*KECCAK_VALUE_W)/16));
	
			keccak_rot(state, sB, (byte)61,(short)((short)(22*KECCAK_VALUE_W)/16),(short)((short)(9*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)56,(short)((short)(23*KECCAK_VALUE_W)/16),(short)((short)(19*KECCAK_VALUE_W)/16));
			keccak_rot(state, sB, (byte)14,(short)((short)(24*KECCAK_VALUE_W)/16),(short)((short)(4*KECCAK_VALUE_W)/16));

			
			/*
				step chi
			*/
			for(y = 0; y != (short)(25*(short)(KECCAK_VALUE_W/16)); y+=(short)(5*(short)(KECCAK_VALUE_W/16))){
				for(x = 0; x != (short)((3*(KECCAK_VALUE_W/16))); x++){
					state[(short)(y + x)].value = (short) (sB[(short)(y + x)].value ^ ((~ sB[(short)(y + x + (1*(KECCAK_VALUE_W/16)))].value) &
							sB[(short)(y + x + (2*(KECCAK_VALUE_W/16)))].value));
				}
				for(x = 0; x != (short)(KECCAK_VALUE_W/16); x++){
					state[(short)((short)(y + (3*(KECCAK_VALUE_W/16)) + x))].value = (short) (sB[(short)(y + (3*(KECCAK_VALUE_W/16)) + x)].value 
							^ ((~ sB[(short)(y + (4*(KECCAK_VALUE_W/16)) + x)].value) & sB[(short)(y + x)].value));
				}
				for(x = 0; x != (short)(KECCAK_VALUE_W/16); x++){
					state[(short)(y + (4*(KECCAK_VALUE_W/16)) + x)].value = (short) (sB[(short)(y + (4*(KECCAK_VALUE_W/16)) + x)].value ^ 
							((~ sB[(short)(y + x)].value) & sB[(short)(y + (1*(KECCAK_VALUE_W/16)) + x)].value));
				}
			}
			/*
				step iota
			*/
			keccak_rc(state, (byte)i);
	}
	}

	
}
