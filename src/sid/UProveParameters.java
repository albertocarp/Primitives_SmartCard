package sid;

import javacard.framework.CardRuntimeException;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class UProveParameters 
{
	
	public  class UproveInternal
	{
		public short internal_size;
		public byte[] value;
	}
		
	public  short MAX_ATTR = 0x05;
	public  short MAX_internal_size=(byte)0xff;
	public  static final short PSIZE_BITS = 1024;
	public  static final short PSIZE_BYTES = (PSIZE_BITS/8);
	public  static final short QSIZE_BITS = 160;
	public  static final short QSIZE_BYTES = (QSIZE_BITS/8);
	public  short T1_LENGTH = 100;
	public  short P1_LENGTH = 100;
	public  short UID_H_LENGTH=100;
	public  short UID_P_LENGTH=100;
	public  short S_LENGTH=100;	
	public   byte[] MAX_ATTR_BYTES = new byte[2];
	public  UproveInternal[] atributes=new UproveInternal[MAX_ATTR];
	public  UproveInternal a  = new UproveInternal(); 
	public	UproveInternal b  = new UproveInternal(); 
	
	/**
	 * This is the transient memory
	 * 20*5 +385
	 */
	
	public  byte[] alpha= JCSystem.makeTransientByteArray(QSIZE_BYTES,JCSystem.CLEAR_ON_DESELECT); 
	public  byte[] beta1=JCSystem.makeTransientByteArray(QSIZE_BYTES,JCSystem.CLEAR_ON_DESELECT); 
	public  byte[] beta2=JCSystem.makeTransientByteArray(QSIZE_BYTES,JCSystem.CLEAR_ON_DESELECT); 
	public byte[] alpha_minus_one =JCSystem.makeTransientByteArray(QSIZE_BYTES,JCSystem.CLEAR_ON_DESELECT); 
	public byte[] w = JCSystem.makeTransientByteArray(QSIZE_BYTES,JCSystem.CLEAR_ON_DESELECT); 
	public  byte[] temp_ram  = JCSystem.makeTransientByteArray((short)384,JCSystem.CLEAR_ON_DESELECT); 
	public  byte[] array  	 =  new byte[2048];
	public  byte[] e_i       =  new byte[MAX_ATTR];  
	public byte[] p = new byte[PSIZE_BYTES];
	public byte[] p_minus_two = new byte[PSIZE_BYTES];
	public byte[] q = new byte[QSIZE_BYTES];
	public byte[] g = new byte[PSIZE_BYTES];
	public byte[] q_minus2 = new byte[PSIZE_BYTES];
	public byte[] t_a = new byte[PSIZE_BYTES];
	public byte[] t_b = new byte[PSIZE_BYTES];
	public UproveInternal[] g_i = new UproveInternal[(short)(MAX_ATTR+2)];
	public byte[] gamma = new byte[PSIZE_BYTES];
	public byte[] h = new byte[PSIZE_BYTES];
	public byte[] sigma_z = new byte[PSIZE_BYTES];
	public byte[] sigma_s_prime = new byte[PSIZE_BYTES];
	public byte[] sigma_a_prime = new byte[PSIZE_BYTES];
	public byte[] sigma_b_prime = new byte[PSIZE_BYTES];
	public byte[] sigma_c_prime = new byte[QSIZE_BYTES];
	public byte[] sigma_c = new byte[QSIZE_BYTES];
	public byte[] sigma_a = new byte[PSIZE_BYTES];
	public byte[] sigma_b = new byte[PSIZE_BYTES];
	public byte[] sigma_r = new byte[PSIZE_BYTES];
	public byte[] sigma_r_prime = new byte[QSIZE_BYTES];
	public byte[] y0 = new byte[QSIZE_BYTES];
	public UproveInternal[] x_i = new UproveInternal[(short)(MAX_ATTR+1)];
	public byte[] TI = new byte[T1_LENGTH];
	public byte[] PI = new byte[P1_LENGTH];
	public byte[] UID_H = new byte[UID_H_LENGTH];
	public byte[] UID_P = new byte[UID_P_LENGTH];
	public byte[] S     = new byte[S_LENGTH];
	
	public void init()
	{
			 for (short s = 0 ; s < (short)(MAX_ATTR + 2);s++)
			 {
				 g_i[s] =  new UproveInternal();
				 g_i[s].value =  new byte[PSIZE_BYTES];
			 }
	}

	public UProveParameters()
	{
		try
		{
			init();
			initAttributes();
			MAX_ATTR_BYTES[0] = (byte)(MAX_ATTR & 0xff);
			MAX_ATTR_BYTES[1] = (byte)((MAX_ATTR >> 8) & 0xff);
			initAttrRaw();
		}
		catch(RuntimeException exception)
		{
			short reason = ((CardRuntimeException) exception).getReason();
		}
	}
	
	private void initAttributes()
	{
	
		for (short s = 0 ; s< MAX_ATTR;s++)
		{
			atributes[s] = new UproveInternal();
			atributes[s].value = new byte[PSIZE_BYTES];
		}
	}

	private void initAttrRaw()
	{
		   short i = 0 ;
		   for ( i = 0 ; i < (short)(MAX_ATTR+1);i++)
		   {
			   x_i[i] = new UproveInternal();
			   x_i[i].value = new byte[20];
		
		   }
	}
}
