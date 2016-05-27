package sid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class JBigInteger {

	public static final boolean use_short_digits = true;
	public static final short size_multiplier = 1;
	public static final short digit_mask = 0xff;
	public static final short digit_first_bit_mask = 0x80;
	public static final short digit_second_bit_mask = 0x40;
	public static final short digit_first_two_bit_mask = 0xC0;
	public static final short digit_len = 8;
	private static final short double_digit_len = 16;
	private static final short positive_double_digit_mask = 0x7fff;
	public static final short highest_digit_bit = (short) (1L << (digit_len - 1));
	public static final short JBigInteger_base = (short) (1L << digit_len);
	public static final short highest_double_digit_bit = (short) (1L << (double_digit_len - 1));
	private byte[] value;

	public byte[] get_digit_array() {
		return value;
	}
	public byte[] as_byte_array() {
		return value;

	}

	private final short size;
	public short size() {
		return (short) (size * size_multiplier);
	}
	
	public short length() {
		return size;
	}
	public JBigInteger(short size, boolean ram) {
		this.size = size;
		if(!ram)
			value = new byte[size];
		else
			value = JCSystem.makeTransientByteArray(size,JCSystem.CLEAR_ON_DESELECT);
		return;
	}

	/**
	 * Stores zero in this object.
	 */
	public void zero() {
		for (short i = 0; i < size; i++)
			value[i] = 0;
	}

	/**
	 * Stores one in this object.
	 */
	public void one() {
		this.zero();
		value[(short) (size - 1)] = 1;
	}

	/**
	 * 
	 * Stores two in this object.
	 */
	public void two() {
		this.zero();
		value[(short) (size - 1)] = 2;
	}

	/**
	 * 
	 * Stores two in this object.
	 */
	public void setLastByte(byte val) {
		this.zero();
		value[(short) (size - 1)] = val;
	}
	public byte getLastByte() {
		return value[(short) (size - 1)];
	}

	public void copy(JBigInteger other) {
		short this_start, other_start, len;
		if (this.size >= other.size) {
			this_start = (short) (this.size - other.size);
			other_start = 0;
			len = other.size;
		} else {
			this_start = 0;
			other_start = (short) (other.size - this.size);
			len = this.size;
		}

		for (short i = 0; i < this_start; i++)
			this.value[i] = 0;

		Util.arrayCopy(other.value, other_start, this.value, this_start, len);
	}
	public boolean same_value(JBigInteger other) {
		for (short i = 0; i < size; i++)
			if (this.value[i] != other.value[i])
				return false;
		return true;
	}

	public static boolean add(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short digit_len = 0x08;
		short result = 0;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);

		for (; i >= xOffset; i--, j--) {
			result = (short) (result + (short) (x[i] & digit_mask) + (short) (y[j] & digit_mask));

			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
		}
		while (result > 0 && i >= xOffset) {
			result = (short) (result + (short) (x[i] & digit_mask));
			x[i] = (byte) (result & digit_mask);
			result = (short) ((result >> digit_len) & digit_mask);
			i--;
		}

		return result != 0;
	}
	public static boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
			short yOffset, short yLength) {
		short digit_mask = 0xff;
		short i = (short) (xLength + xOffset - 1);
		short j = (short) (yLength + yOffset - 1);
		short carry = 0;
		short subtraction_result = 0;

		for (; i >= xOffset && j >= yOffset; i--, j--) {
			subtraction_result = (short) ((x[i] & digit_mask)
					- (y[j] & digit_mask) - carry);
			x[i] = (byte) (subtraction_result & digit_mask);
			carry = (short) (subtraction_result < 0 ? 1 : 0);
		}
		for (; i >= xOffset && carry > 0; i--) {
			if (x[i] != 0)
				carry = 0;
			x[i] -= 1;
		}

		return carry > 0;
	}
	public void times_minus(JBigInteger other, short shift, short mult) {
		short akku = 0;
		short subtraction_result;
		short i = (short) (this.size - 1 - shift);
		short j = (short) (other.size - 1);
		for (; i >= 0 && j >= 0; i--, j--) {
			akku = (short) (akku + (short) (mult * (other.value[j] & digit_mask)));
			subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));
			value[i] = (byte) (subtraction_result & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
			if (subtraction_result < 0)
				akku++;
		}

		// deal with carry as long as there are digits left in this
		while (i >= 0 && akku != 0) {
			subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));
			value[i] = (byte) (subtraction_result & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
			if (subtraction_result < 0)
				akku++;
			i--;
		}

		return;
	}

	private static short highest_bit(short x) {
		for (short i = 0; i < double_digit_len; i++) {
			if (x < 0)
				return i;
			x <<= 1;
		}
		return double_digit_len;
	}

	private static short shift_bits(short high, byte middle, byte low,
			short shift) {

		// shift high
		high <<= shift;

		// merge middle bits
		byte mask = (byte) (digit_mask << (shift >= digit_len ? 0 : digit_len
				- shift));
		short bits = (short) ((short) (middle & mask) & digit_mask);
		if (shift > digit_len)
			bits <<= shift - digit_len;
		else
			bits >>>= digit_len - shift;
		high |= bits;

		if (shift <= digit_len) {

			return high;
		}

		// merge low bits
		mask = (byte) (digit_mask << double_digit_len - shift);
		bits = (short) ((((short) (low & mask) & digit_mask) >> double_digit_len
				- shift));
		high |= bits;

		return high;
	}

	public boolean shift_lesser(JBigInteger other, short shift, short start) {
		short j;

		j = (short) (other.size + shift - this.size + start);

		short this_short, other_short;
		for (short i = start; i < this.size; i++, j++) {
			this_short = (short) (this.value[i] & digit_mask);
			if (j >= 0 && j < other.size)
				other_short = (short) (other.value[j] & digit_mask);
			else
				other_short = 0;
			if (this_short < other_short)
				return true;
			if (this_short > other_short)
				return false;
		}
		return false;
	}

	/**
	 * Comparison.
	 * 
	 * @param other
	 *            JBigInteger to compare with
	 * @return true if this number is strictly lesser than {@code other}, false
	 *         otherwise.
	 */
	// Return true, if this < other, false otherwise.
	public boolean lesser(JBigInteger other) {
		return this.shift_lesser(other, (short) 0, (short) 0);
	}

	/**
	 * Test equality with zero.
	 * 
	 * @return true if this JBigInteger equals zero.
	 */
	public boolean is_zero() {
		for (short i = 0; i < size; i++) {
			if (value[i] != 0)
				return false;
		}
		return true;
	}
	public void remainder_divide(JBigInteger divisor, JBigInteger quotient) {
		if (quotient != null)
			quotient.zero();
		short divisor_index = 0;
		while (divisor.value[divisor_index] == 0)
			divisor_index++;

		short divisor_shift = (short) (this.size - divisor.size + divisor_index);
		short division_round = 0;
		short first_divisor_digit = (short) (divisor.value[divisor_index] & digit_mask);
		short divisor_bit_shift = (short) (highest_bit((short) (first_divisor_digit + 1)) - 1);
		byte second_divisor_digit = divisor_index < (short) (divisor.size - 1) ? divisor.value[(short) (divisor_index + 1)]
				: 0;
		byte third_divisor_digit = divisor_index < (short) (divisor.size - 2) ? divisor.value[(short) (divisor_index + 2)]
				: 0;
		short divident_digits, divisor_digit;
		short divident_bit_shift, bit_shift;
		short multiple, quotient_digit;
		while (divisor_shift >= 0) {
			while (!shift_lesser(divisor, divisor_shift,
					(short) (division_round > 0 ? division_round - 1 : 0))) {
				divident_digits = division_round == 0 ? 0
						: (short) ((short) (value[(short) (division_round - 1)]) << digit_len);
				divident_digits |= (short) (value[division_round] & digit_mask);
				if (divident_digits < 0) {
					divident_digits = (short) ((divident_digits >>> 1) & positive_double_digit_mask);
					divisor_digit = (short) ((first_divisor_digit >>> 1) & positive_double_digit_mask);
				} else {
					divident_bit_shift = (short) (highest_bit(divident_digits) - 1);
					bit_shift = divident_bit_shift <= divisor_bit_shift ? divident_bit_shift
							: divisor_bit_shift;

					divident_digits = shift_bits(
							divident_digits,
							division_round < (short) (this.size - 1) ? value[(short) (division_round + 1)]
									: 0,
							division_round < (short) (this.size - 2) ? value[(short) (division_round + 2)]
									: 0, bit_shift);
					divisor_digit = shift_bits(first_divisor_digit,
							second_divisor_digit, third_divisor_digit,
							bit_shift);

				}

				// add one to divisor to avoid underflow
				multiple = (short) (divident_digits / (short) (divisor_digit + 1));
				if (multiple < 1)
					multiple = 1;

				times_minus(divisor, divisor_shift, multiple);
				if (quotient != null) {
					quotient_digit = (short) ((quotient.value[(short) (quotient.size - 1 - divisor_shift)] & digit_mask) + multiple);
					quotient.value[(short) (quotient.size - 1 - divisor_shift)] = (byte) (quotient_digit);
				}
			}

			// treat loop indices
			division_round++;
			divisor_shift--;
		}
	}
	public boolean add_carry(JBigInteger other) {
		short akku = 0;
		short j = (short) (this.size - 1);
		for (short i = (short) (other.size - 1); i >= 0; i--, j--) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (other.value[i] & digit_mask));

			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
		}
		// add carry at position j
		while (akku > 0 && j >= 0) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask));
			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
			j--;
		}

		return akku != 0;
	}

	public void add(JBigInteger other) {
		if (add_carry(other)) {
		}
	}
	public void times_add(JBigInteger other, short mult) {
		short akku = 0;
		for (short i = (short) (size - 1); i >= 0; i--) {
			akku = (short) (akku + (short) (this.value[i] & digit_mask) + (short) (mult * (other.value[i] & digit_mask)));
			this.value[i] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
		}
		return;
	}
	public void times_add_shift(JBigInteger other, short shift, short mult) {

		short akku = 0;
		short j = (short) (this.size - 1 - shift);
		for (short i = (short) (other.size - 1); i >= 0; i--, j--) {
			akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (mult * (other.value[i] & digit_mask)));

			this.value[j] = (byte) (akku & digit_mask);
			akku = (short) ((akku >> digit_len) & digit_mask);
		}
		// add carry at position j
		akku = (short) (akku + (short) (this.value[j] & digit_mask));
		this.value[j] = (byte) (akku & digit_mask);
		// assert no overflow
		return;
	}
	public void mult(JBigInteger x, JBigInteger y) {
		this.zero();
		for (short i = (short) (y.size - 1); i >= 0; i--) {
			this.times_add_shift(x, (short) (y.size - 1 - i),
					(short) (y.value[i] & digit_mask));
		}
		return;
	}

	public void shift_left() {
		Util.arrayCopy(this.value, (short) 1, this.value, (short) 0,
				(short) (size - 1));

		value[(short) (size - 1)] = 0;
	}
	public void mult_mod(JBigInteger x, JBigInteger y, JBigInteger mod) {
		this.zero();
		for (short i = 0; i < y.size; i++) {

			this.shift_left();

			this.times_add(x, (short) (y.value[i] & digit_mask));

			this.remainder_divide(mod, null);
		}
		return;
	}
	public void shift_right() {
	         Util.arrayCopy(this.value, (short)0, this.value, (short)1, 
                     (short)(size -1));
	        
	        value[0] = 0;
	    }

	public void div_2() {
		short carry = 0;
		for (short i = 0; i < this.size; i++) {
			if ((this.value[i] & 0x01) == 0) {
				this.value[i] = (byte) (((this.value[i] & digit_mask) >> 1) | carry);
				carry = 0;
			} else {
				this.value[i] = (byte) (((this.value[i] & digit_mask) >> 1) | carry);
				carry = digit_first_bit_mask;
			}
		}
	}

	public static short modular_division_by_2(byte[] input, short inOffset,
			short inLength, byte[] modulos, short modOffset, short modLength) {
		short carry = 0;
		short digit_mask = 0xff;
		short digit_first_bit_mask = 0x80;
		short lastIndex = (short) (inOffset + inLength - 1);

		short i = inOffset;
		if ((byte) (input[lastIndex] & 0x01) != 0) {
			if (JBigInteger.add(input, inOffset, inLength, modulos, modOffset,
					modLength)) {
				carry = digit_first_bit_mask;
			}
		}

		for (; i <= lastIndex; i++) {
			if ((input[i] & 0x01) == 0) {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = 0;
			} else {
				input[i] = (byte) (((input[i] & digit_mask) >> 1) | carry);
				carry = digit_first_bit_mask;
			}
		}
		return carry;
		
	}

	public boolean is_compatible_with(Object o) {
		if (o instanceof JBigInteger) {
			return this.size() == ((JBigInteger) o).size();
		}
		return false;
	}

	public short to_byte_array(short len, short this_index,
			byte[] byte_array, short short_index) {
		short max = (short) (this_index + len) <= this.size ? len
				: (short) (this.size - this_index);
		Util.arrayCopy(value, this_index, byte_array, short_index, max);
		if ((short) (this_index + len) == this.size)
			return (short) (len + 1);
		else
			return max;
	}


    public short from_byte_array(short len, short this_index,
                                 byte[] byte_array, short byte_index) {
        short max = 
            (short)(this_index + len) <= this.size ? 
                      len : (short)(this.size - this_index);
        Util.arrayCopy(byte_array, byte_index, value, this_index, max);
        if((short)(this_index + len) == this.size)
            return (short)(len + 1);
        else
            return max;
    }


	public static JBigInteger valueOf(short size, byte b) {
		JBigInteger tmp = new JBigInteger(size, false);
		tmp.setLastByte(b);
		return tmp;
	}

}
