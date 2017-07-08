package purse;
/**
 * 已给出部分常数值，其他根据需要自行添加 
 */
public class condef {
	//----------------- INS Byte -------------------
	final static byte INS_CREATE_FILE     = (byte)0xE0;         //文件建立命令的INS值
	final static byte INS_WRITE_KEY       = (byte)0xD4;         //写入密钥命令的INS值
	final static byte INS_WRITE_BIN       = (byte)0xD6;         //写入二进制命令的INS值
	final static byte INS_READ_BIN		  = (byte)0xB0;			//读二进制文件(lxs)
	
	final static byte INS_NIIT_TRANS      = (byte)0x50;         //初始化圈存和初始化消费命令的INS值
	final static byte INS_LOAD            = (byte)0x52;         //圈存命令的INS值
	final static byte INS_PURCHASE		  = (byte)0x54;			//消费命令(lxs)
	final static byte INS_GET_BALANCE     = (byte)0x5c;			//读余额(lxs)
	
	//final static byte P_KEY               = (byte)0x60;         //计算过程密钥
    //final static byte MAC                 = (byte)0x62;         //计算MAC
    
	// INS for test (lxs)
	final static byte INS_TEST  		  = (byte)0xEF;
	
	//－－－－－－－－－－－－－－　FILE TYPE Byte ---------------
	final static byte KEY_FILE            = (byte)0x3F;         //密钥文件的文件类型
	final static byte CARD_FILE           = (byte)0x38;         //应用基本文件的文件类型
	final static byte PERSON_FILE         = (byte)0x39;         //持卡人基本文件 的文件类型
	final static byte EP_FILE             = (byte)0x2F;         //电子钱包文件的文件类型
	
	//------------------------ SW --------------------- 
	final static short SW_LOAD_FULL = (short)0x9501;      		//圈存超额	
	final static short SW_BALANCE_NOT_ENOUGH = (short)0x9401;   //消费余额不足
}
