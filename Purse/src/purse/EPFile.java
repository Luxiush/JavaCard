package purse;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EPFile {
	private KeyFile keyfile;
	
	//内部数据元
	private byte[] EP_balance;         //电子钱包余额
	private byte[] EP_offline;         //电子钱包联机交易序号
	private byte[] EP_online;          //电子钱包脱机交易序号
	
	byte keyID;        //密钥版本号
	byte algID;        //算法标识符
	
	//安全系统设计
	private Randgenerator RandData;          //随机数产生
	private PenCipher EnCipher;              //数据加解密方式实现
/**
 * 下面数据是计算时需要用到的临时过程数据	
 */
	//临时计算数据
	//4个字节的临时计算数据
	private byte[] pTemp41;           
	private byte[] pTemp42;
	
	//8个字节的临时计算数据
	private byte[] pTemp81;
	private byte[] pTemp82;
	
	//32个字节的临时计算数据
	private byte[] pTemp16;
	private byte[] pTemp32;
	
	public EPFile(KeyFile keyfile){
		EP_balance = new byte[4];
		Util.arrayFillNonAtomic(EP_balance, (short)0, (short)4, (byte)0x00);
		
		EP_offline = new byte[2];
		Util.arrayFillNonAtomic(EP_offline, (short)0, (short)2, (byte)0x00);
		
		EP_online = new byte[2];
		Util.arrayFillNonAtomic(EP_online, (short)0, (short)2, (byte)0x00);
		
		this.keyfile = keyfile;
		
		pTemp41 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		pTemp42 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		
		pTemp81 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		pTemp82 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		
		pTemp16 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
		pTemp32 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
		
		RandData = new Randgenerator();
		EnCipher = new PenCipher();
	}
	
	/*
	 * 功能：电子钱包金额的增加
	 * 参数：data 所增加的金额  
	 * 	   flag 是否真正增加电子钱包余额
	 * 返回：圈存后，余额是否超过最大限额
	 */
	public final short increase(byte[] data, boolean flag){
		short i, t1, t2, ads;
		
		ads = (short)0;
		for(i = 3; i >= 0; i --){
			t1 = (short)(EP_balance[(short)i] & 0xFF);
			t2 = (short)(data[i] & 0xFF);
			
			t1 = (short)(t1 + t2 + ads);
			if(flag)
				EP_balance[(short)i] = (byte)(t1 % 256);
			ads = (short)(t1 / 256);
		}
		return ads;
	}
	
	/*
	 * 功能：圈存初始化功能完成
	 * 参数：num 密钥记录号， data 命令报文中的数据段
	 * 返回：0： 圈存初始化命令执行成功     2：圈存超过电子钱包最大限额
	 */
	public final short init4load(short num, byte[] data){
		short length,rc;
		
		Util.arrayCopyNonAtomic(data, (short)1, pTemp42, (short)0, (short)4);  //交易金额
		Util.arrayCopyNonAtomic(data, (short)5, pTemp81, (short)0, (short)6);  //终端机编号
		
		//判断是否超额圈存
		rc = increase(pTemp42, false);
		if(rc != (short)0)
			return (short)2;
		
		//密钥获取
		length = keyfile.readkey(num, pTemp32);
		keyID = pTemp32[3];
		algID = pTemp32[4];
		Util.arrayCopyNonAtomic(pTemp32, (short)5, pTemp16, (short)0, length);//圈存密钥
		
		//产生随机数(4byte)
		RandData.GenerateSecureRnd();
		RandData.getRndValue(pTemp32, (short)0);
		
		//产生过程密钥
		Util.arrayCopyNonAtomic(EP_online, (short)0, pTemp32, (short)4, (short)2); //电子钱包联机交易序号
		
		pTemp32[6] = (byte)0x80; //0x8000
		pTemp32[7] = (byte)0x00;
		
		//                 圈存密钥            数据                                                                                             过程密钥
		EnCipher.gen_SESPK(pTemp16, pTemp32, (short)0, (short)8, pTemp82, (short)0); 
		
		//产生MAC1
			//mac1 data
		Util.arrayCopyNonAtomic(EP_balance, (short)0, pTemp32, (short)0, (short)4);   //电子钱包余额(4byte)
		Util.arrayCopyNonAtomic(data, (short)1, pTemp32, (short)4, (short)4);         //交易金额(4byte)
		pTemp32[8] = (byte)0x02;                                                      //交易类型标识(1byte)
		Util.arrayCopyNonAtomic(data, (short)5, pTemp32, (short)9, (short)6);         //终端机编号(6byte)
			
		//Util.arrayCopyNonAtomic(pTemp32, (short)0, data, (short)0x00, (short)0x0F);   // ??
		//             过程密钥  数据                 MAC1
		EnCipher.gmac4(pTemp82, pTemp32, (short)0x0F, pTemp41);
		
		//响应数据
		Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);      //电子钱包余额        [0...3]
		Util.arrayCopyNonAtomic(EP_online, (short)0, data,  (short)4, (short)2);      //电子钱包联机交易序号[4...5]
		data[6] = keyID;                                                              //密钥版本号          [6]
		data[7] = algID;                                                              //算法标识            [7]
		RandData.getRndValue(data, (short)8);                                         //随机数              [8...11]   
		Util.arrayCopyNonAtomic(pTemp41, (short)0, data, (short)12, (short)4);        //mac1                [12...15]
		
		//把过程密钥也传回去--测试过程密钥时使用
		Util.arrayCopyNonAtomic(pTemp82, (short)0, data, (short)16, (short)8);        //将过程密钥赋给data[16]~data[23];
		//把gmac4的data参数返回
		data[24] = (byte)0x88;
		Util.arrayCopyNonAtomic(pTemp32, (short)0, data, (short)25, (short)15);
		
		return 0;
	}
	
	/*
	 * 功能：圈存功能的完成
	 * 参数：data 命令报文中的数据段
	 * 返回：0 圈存命令执行成功；1 MAC2校验错误；  2 圈存超过最大限额; 3 密钥未找到
	 */
	public final short load(byte[] data){
		short rc;
		
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);       //交易金额
		pTemp32[4] = (byte)0x02;                                                       //交易标识
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)5, (short)6);       //终端机编号
		Util.arrayCopyNonAtomic(data, (short)0, pTemp32, (short)11, (short)7);         //交易日期与时间
		EnCipher.gmac4(pTemp82, pTemp32, (short)0x12, pTemp41);
		
		//检验MAC2
		if(Util.arrayCompare(data, (short)7, pTemp41, (short)0, (short)4) != (byte)0x00)
			return (short)1;
		
		//电子钱包数目增加
		rc = increase(pTemp42, true);
		if(rc != (short)0)
			return 2;
		
		//TAC数据
		Util.arrayCopyNonAtomic(EP_balance, (short)0, pTemp32, (short)0, (short)4);    //电子钱包余额
		Util.arrayCopyNonAtomic(EP_online, (short)0, pTemp32, (short)4, (short)2);     //电子钱包联机交易序号
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)6, (short)4);       //交易金额
		pTemp32[10] = (byte)0x02;                                                      //交易类型
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)11, (short)6);      //终端机编号
		Util.arrayCopyNonAtomic(data, (short)0, pTemp32, (short)17, (short)7);         //交易日期与时间
		
		//联机交易序号加1
		rc = Util.makeShort(EP_online[0], EP_online[1]);
		rc ++;
		if(rc > (short)256)
			rc = (short)1;
		Util.setShort(EP_online, (short)0, rc);
		
		//TAC的计算
		short length, num;
		num = keyfile.findKeyByType((byte)0x34);
		length = keyfile.readkey(num, pTemp16);
		
		if(length == 0)
			return (short)3;
		
		Util.arrayCopyNonAtomic(pTemp16, (short)5, pTemp82, (short)0, (short)8);
		
		EnCipher.xorblock8(pTemp82, pTemp16, (short)13);
		EnCipher.gmac4(pTemp82, pTemp32, (short)0x18, data);
		
		return (short)0;
	}
		/*
	 * 功能：电子钱包金额减少
	 * 参数：data 消费的金额； flag 是否真正扣减电子钱包余额
	 * 返回： 消费是否超额
	 */
	public final short decrease(byte[] data, boolean flag){
		short t1, t2, ads;
		ads = (short)0;
		for(short i = 3; i >= 0; i--){
			//因为EP_balance[i]和data[i]是一个字节,而short为两个字节，所以要补0xFF
			t1 = (short)(EP_balance[(short)i] & 0xFF);
			t2 = (short)(data[i] & 0xFF);
			short temp = t1;
			t1 = (short)(t1 - t2 - ads);	//当前位 = 原值 - 对应位置消费值 - 借位 
			
			if(t1 >= 0) ads = 0;			//是否向前一位借1
			else ads = 1;
			
			if(flag){
				EP_balance[(short)i] = (byte)(t1 % 256);
			}
		}
		
		return ads;
	}
		
	/*
	 * 功能：消费初始化命令的完成
	 * 参数：num 密钥记录号； data 命令报文中的数据段
	 * 返回：0 命令执行成功；2 消费超额
	 */
	public final short init4purchase(short num, byte[] data){
		short length,rc;
		
		Util.arrayCopyNonAtomic(data, (short)1, pTemp42, (short)0, (short)4);  //交易金额存进pTemp42
		Util.arrayCopyNonAtomic(data, (short)5, pTemp81, (short)0, (short)6);  //终端机编号存进pTemp81
		
		//判断余额是否足够,此时不修改余额
		rc = decrease(pTemp42, false);
		if(rc != (short)0)
			return (short)2;//余额不足返回2
		
		//密钥获取
		length = keyfile.readkey(num, pTemp32);
		keyID = pTemp32[3];
		algID = pTemp32[4];
		Util.arrayCopyNonAtomic(pTemp32, (short)5, pTemp16, (short)0, length);			//获取之前存进文件的消费密钥,存在pTemp16中
		
		//产生随机数
		RandData.GenerateSecureRnd();
		RandData.getRndValue(pTemp32, (short)0);										//产生随机数放在PTemp32
		
		//返回响应数据,全部在这赋值了
		Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);      	//电子钱包余额data[0]~data[3]
		Util.arrayCopyNonAtomic(EP_offline, (short)0, data,  (short)4, (short)2);     	//电子钱包脱机交易序号data[4]~data[5]
		byte[] touzhi = {0x00,0x00,0x00};
		Util.arrayCopyNonAtomic(touzhi, (short)0, data,  (short)6, (short)3);      	  	//透支限额data[6]~data[8]
		data[9] = keyID;                                                              	//密钥版本号data[9]
		data[10] = algID;                                                             	//算法标识data[10]
		RandData.getRndValue(data, (short)11);                                        	//将随机数赋给data[11]~data[14]
		
		return 0;
		
	}
	/*
	 * 功能：消费命令的实现
	 * 参数：data 命令报文中的数据段
	 * 返回：0 命令执行成功； 1 MAC校验错误 2 消费超额； 3 密钥未找到
	 */
	public final short purchase(byte[] data){
		short rc;
		//消费密钥之前已经存进了pTemp16
		//伪随机数之前已经存进了pTemp32
		
		//产生过程密钥
		Util.arrayCopyNonAtomic(EP_offline, (short)0, pTemp32, (short)4, (short)2);		//pTemp32[4]~[5]赋值的是脱机交易序列号EP_offline
		Util.arrayCopyNonAtomic(data, (short)2, pTemp32, (short)6, (short)2);			//pTemp32[6]~[7]赋值的是终端交易序号的最后两个字节
		
		EnCipher.gen_SESPK(pTemp16, pTemp32, (short)0, (short)8, pTemp82, (short)0); 	//pTemp82为得到的过程密钥
		
		//产生MAC1
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);   		//交易金额pTemp32[0]~pTemp32[3]
		pTemp32[4] = (byte)0x06;                                                      	//交易类型标识pTemp32[4]
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)5, (short)6);        //终端机编号pTemp32[5]~pTemp32[10]
		Util.arrayCopyNonAtomic(data, (short)4, pTemp32, (short)11, (short)7);			//交易日期和时间pTemp32[11]~[17]
		
		
		EnCipher.gmac4(pTemp82, pTemp32, (short)18, pTemp41);							//产生mac1并存储在pTemp41,data为pTemp32
		
		//检验MAC1
		if(Util.arrayCompare(data, (short)11, pTemp41, (short)0, (short)4) != (byte)0x00)
			return (short)1;	//不相同则返回1
			
		
		//脱机交易序号加1
		rc = Util.makeShort(EP_offline[0], EP_offline[1]);
		rc ++;
		if(rc > (short)256)
			rc = (short)1;
		Util.setShort(EP_offline, (short)0, rc);
		
		//电子钱包金额减少
		rc = decrease(pTemp42, true);
		if(rc != (short)0)
			return (short)2;
	
		//MAC2生成
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);       	//交易金额作为数据输入pTemp32[0]~[3]
		EnCipher.gmac4(pTemp82, pTemp32, (short)4, pTemp41);							//得到mac2存进pTemp41,注意这里会把数据pTemp32修改!
		
		
		//TAC数据
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);       	//交易金额[0]~[3]
		pTemp32[4] = (byte)0x06;                                                       	//交易类型标识[4]
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)5, (short)6);     	//终端机编号[5]~[10]
		Util.arrayCopyNonAtomic(data, (short)0, pTemp32, (short)11, (short)4);     		//终端交易序号[11]~[14]
		Util.arrayCopyNonAtomic(data, (short)4, pTemp32, (short)15, (short)7);			//交易日期与时间[15]~[21],注意必须要在返回mac2之前（会修改data位!）!
		
		//TAC的计算
		short length, num;
		num = keyfile.findKeyByType((byte)0x34);
		length = keyfile.readkey(num, pTemp16);
		
		if(length == 0)
			return (short)3;
		Util.arrayCopyNonAtomic(pTemp16, (short)5, pTemp82, (short)0, (short)8);//去掉前五位密钥头部
		EnCipher.xorblock8(pTemp82, pTemp16, (short)13);						//密钥左8位和右8位异或得到新密钥
				
		//得到tac同时返回tac给终端
		byte[] temp = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopyNonAtomic(pTemp82, (short)0, temp, (short)0, (short)8);//pTtem16[13]开始才是密钥
		
		//返回mac2
		Util.arrayCopyNonAtomic(pTemp41, (short)0, data, (short)4, (short)4);
		Util.arrayCopyNonAtomic(temp, (short)0, data, (short)8, (short)8);
		EnCipher.gmac4(temp, pTemp32, (short)22, data);//得到tac直接复制给data返回了
		
		return 0;
	}
	/*
	 * 功能：电子钱包余额获取
	 * 参数：data 电子钱包余额的缓冲区
	 * 返回： 0
	 */
	public final short get_balance(byte[] data){
		for(short i = 0;i < 4;i++)
		{
			data[i] = EP_balance[i];
		}
		return 0;
	}
}
