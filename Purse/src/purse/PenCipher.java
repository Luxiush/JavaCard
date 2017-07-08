package purse;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class PenCipher {
	private Cipher desEngine;
	private Key deskey;
	
	public PenCipher(){
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	}
	
	/*
	 * 功能：DES运算
	 * 参数：key 密钥; kOff 密钥的偏移量; data 所要进行加解密的数据; dOff 数据偏移量； dLen 数据的长度; r 加解密后的数据缓冲区； rOff 结果数据偏移量； mode 加密或解密运算模式
	 * 返回：无
	 */
	public final void cdes(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode){
		//设置ＤＥＳ密钥
		((DESKey)deskey).setKey(akey, kOff);
		//初始化密钥及加密模式
		desEngine.init(deskey, mode);
		//加密
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	/*
	 * 功能：生成过程密钥 (8byte)
	 * 参数：key 密钥； data 所要加密的数据； dOff 所加密的数据偏移量； dLen 所加密的数据长度； r 加密后的数据； rOff 加密后的数据存储偏移量
	 * 返回：无
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff){
		//todo 3次des运算
		byte[] buf = JCSystem.makeTransientByteArray((short)dLen, JCSystem.CLEAR_ON_DESELECT);
		short bOff = 0;
		cdes(key,(short)0,data,dOff,dLen,r,  rOff,Cipher.MODE_ENCRYPT);
		cdes(key,(short)8,r,   rOff,dLen,buf,bOff,Cipher.MODE_DECRYPT);//加密后的数据长度和加密前的一致 ，DES
		cdes(key,(short)0,buf, bOff,dLen,r,  rOff,Cipher.MODE_ENCRYPT);
	}
	
	/*
	 * 功能：8个字节的异或操作
	 * 参数：d1 进行异或操作的数据1 d2:进行异或操作的数据2 d2_off:数据2的偏移量
	 * 返回：无
	 */
	public final void xorblock8(byte[] d1, byte[] d2, short d2_off){
		//todo: 两个数据块进行异或，异或结果存入数据块d1中
		for(short i=0; i<8; i++){
			d1[i] = (byte)(d1[i]^d2[i+d2_off]);
		}
	}
	
	/*
	 * 功能：字节填充
	 * 参数：data 所要填充的数据； len 数据的长度
	 * 返回：填充后的字节长度
	 */
	public final short pbocpadding(byte[] data, short len){
		//todo: 填充字符串至8的倍数
		//data的空间是否充足，是否需要分配新的空间??   最大255byte,足够
		
		data[len] = (byte)0x80;
		len ++;
		
		while(len % 8 != 0){
			data[len] = (byte)0x00;
			len++;
		}
		
		return len;
	}
	
	/*
	 * 功能：MAC和TAC的生成
	 * 参数：key 密钥; data 所要加密的数据; dl 所要加密的数据长度； mac 所计算得到的MAC和TAC码
	 * 返回：无
	 */
	public final void gmac4(byte[] key, byte[] data, short dl, byte[] mac){
		//todo：生成MAC和TAC
		byte[] buf = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		for(short i=0; i<(short)8; i++) buf[i] = (byte)0x00;
		
		short dl2 = pbocpadding(data,dl);
		
		for(short off=0; off<dl2; off+=(short)8){
			xorblock8(buf,data,off);
			cdes(key,(short)0, buf,(short)0, (short)8, buf,(short)0, Cipher.MODE_ENCRYPT);
		}
		
		for(short i=0; i<4; i++) mac[i] = buf[i];
	}
}
