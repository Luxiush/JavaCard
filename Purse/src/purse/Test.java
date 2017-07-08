package purse;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Test{
	private final static byte T_Pen_pbocpadding		= (byte)0x01;	
	private final static byte T_Pen_xorblock8		= (byte)0x02;
	private final static byte T_Pen_gen_SESPK		= (byte)0x03;
	private final static byte T_Pen_gmac4			= (byte)0x04;
	
	private final static byte T_Key_readkey			= (byte)0x05;
	
	private final static byte DELIMETER = (byte)0x88;
	
	/*************/
	private PenCipher pencipher;
	
	private short ins; //java short类型有2个byte ???
	
	
	/*************/
	public Test(){
		pencipher = new PenCipher();
	}
	
	//实现自定义指令
	public boolean test(Papdu p, KeyFile kf){
		switch (p.p1){
			case T_Pen_pbocpadding:// /send 00ef010002aaaa0a
				pencipher.pbocpadding(p.pdata, p.lc);
				return true;
			
			case T_Pen_xorblock8://  /send 00ef020010aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb10
				pencipher.xorblock8(p.pdata, p.pdata, (short)8);
				return true;
			
			case T_Pen_gen_SESPK://  /send 00 ef 03 00 lc key_left(8byte) key_right&&data(8byte) le
								 //  /send 00ef030010aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb18
				pencipher.gen_SESPK(p.pdata, p.pdata, (short)8, (short)8, p.pdata, (short)16);
				return true;
				
			case T_Pen_gmac4:
				// /send 00ef040020AAAAAAAAAAAAAAAA55555555555555556666666666666666777777777777777728
				// /send 00 ef o4 00 lc key data le 
				// key = pdata[0...7]; data = pdata[8...8+p2]; pdata[8+p2...8+p2+8] = mac
				short dl = (short)(p.lc-8);
				byte[] key = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
				Util.arrayCopyNonAtomic(p.pdata, (short)0, key, (short)0, (short)8);
			
				byte[] data = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);
				Util.arrayCopyNonAtomic(p.pdata, (short)8, data, (short)0, dl);
				
				byte[] mac = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
				pencipher.gmac4(key, data, dl, mac);
				
				Util.arrayCopyNonAtomic(mac, (short)(0), p.pdata, (short)(8+dl), (short)8);
				p.le = (short)(p.lc+8);
				
				return true;			
			
			case T_Key_readkey://读取密钥文件    /send 00ef 0500 00 0001 00
				byte type = p.pdata[0];//密钥类型
				byte[] buf = JCSystem.makeTransientByteArray((short)(255), JCSystem.CLEAR_ON_DESELECT);
				short length = kf.readkey(kf.findKeyByType(type), buf);
				Util.arrayCopyNonAtomic(buf, (short)5, p.pdata, (short)2, length);
				p.le = (short)(length+2);
				
				return true;
				
			default:
				ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
				return false;
		}
	}
}