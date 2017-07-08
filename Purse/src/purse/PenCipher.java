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
	 * ���ܣ�DES����
	 * ������key ��Կ; kOff ��Կ��ƫ����; data ��Ҫ���мӽ��ܵ�����; dOff ����ƫ������ dLen ���ݵĳ���; r �ӽ��ܺ�����ݻ������� rOff �������ƫ������ mode ���ܻ��������ģʽ
	 * ���أ���
	 */
	public final void cdes(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode){
		//���ãģţ���Կ
		((DESKey)deskey).setKey(akey, kOff);
		//��ʼ����Կ������ģʽ
		desEngine.init(deskey, mode);
		//����
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	/*
	 * ���ܣ����ɹ�����Կ (8byte)
	 * ������key ��Կ�� data ��Ҫ���ܵ����ݣ� dOff �����ܵ�����ƫ������ dLen �����ܵ����ݳ��ȣ� r ���ܺ�����ݣ� rOff ���ܺ�����ݴ洢ƫ����
	 * ���أ���
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff){
		//todo 3��des����
		byte[] buf = JCSystem.makeTransientByteArray((short)dLen, JCSystem.CLEAR_ON_DESELECT);
		short bOff = 0;
		cdes(key,(short)0,data,dOff,dLen,r,  rOff,Cipher.MODE_ENCRYPT);
		cdes(key,(short)8,r,   rOff,dLen,buf,bOff,Cipher.MODE_DECRYPT);//���ܺ�����ݳ��Ⱥͼ���ǰ��һ�� ��DES
		cdes(key,(short)0,buf, bOff,dLen,r,  rOff,Cipher.MODE_ENCRYPT);
	}
	
	/*
	 * ���ܣ�8���ֽڵ�������
	 * ������d1 ����������������1 d2:����������������2 d2_off:����2��ƫ����
	 * ���أ���
	 */
	public final void xorblock8(byte[] d1, byte[] d2, short d2_off){
		//todo: �������ݿ�������������������ݿ�d1��
		for(short i=0; i<8; i++){
			d1[i] = (byte)(d1[i]^d2[i+d2_off]);
		}
	}
	
	/*
	 * ���ܣ��ֽ����
	 * ������data ��Ҫ�������ݣ� len ���ݵĳ���
	 * ���أ�������ֽڳ���
	 */
	public final short pbocpadding(byte[] data, short len){
		//todo: ����ַ�����8�ı���
		//data�Ŀռ��Ƿ���㣬�Ƿ���Ҫ�����µĿռ�??   ���255byte,�㹻
		
		data[len] = (byte)0x80;
		len ++;
		
		while(len % 8 != 0){
			data[len] = (byte)0x00;
			len++;
		}
		
		return len;
	}
	
	/*
	 * ���ܣ�MAC��TAC������
	 * ������key ��Կ; data ��Ҫ���ܵ�����; dl ��Ҫ���ܵ����ݳ��ȣ� mac ������õ���MAC��TAC��
	 * ���أ���
	 */
	public final void gmac4(byte[] key, byte[] data, short dl, byte[] mac){
		//todo������MAC��TAC
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
