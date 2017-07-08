package purse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Purse extends Applet {
	//APDU Object
	private Papdu papdu;
	
	//文件系统
	private KeyFile keyfile;            //密钥文件
	private BinaryFile cardfile;       //应用基本文件
	private BinaryFile personfile;     //持卡人基本文件
	private EPFile EPfile;              //电子钱包文件
	
	private Test T;
	
	public Purse(byte[] bArray, short bOffset, byte bLength){
		papdu = new Papdu();
		
		byte aidLen = bArray[bOffset];
		if(aidLen == (byte)0x00)
			register();
		else
			register(bArray, (short)(bOffset + 1), aidLen);
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Purse(bArray, bOffset, bLength);
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}		
		//步骤1:取APDU缓冲区数组引用并将之赋给新建数组
		byte[] buf = apdu.getBuffer();//getBuffer返回的是缓冲区的引用，通过buf可以直接修改缓冲区
		//步骤2：取APDU缓冲区中数据放到变量papdu
		apdu.setIncomingAndReceive(); 
		papdu.cla = buf[ISO7816.OFFSET_CLA];
		papdu.ins = buf[ISO7816.OFFSET_INS];
		papdu.p1 = buf[ISO7816.OFFSET_P1];
		papdu.p2 = buf[ISO7816.OFFSET_P2];		
		
		//步骤3：判断命令APDU是否包含数据段，有数据则获取数据长度，并对le赋值，否则，即不需要lc和data，则获取缓冲区原本lc实际上是le
		if(papdu.APDUContainData()){
			papdu.lc = buf[ISO7816.OFFSET_LC];
			Util.arrayCopyNonAtomic(buf, (short)ISO7816.OFFSET_CDATA, papdu.pdata, (short)0, papdu.lc);
			papdu.le = buf[ISO7816.OFFSET_CDATA+papdu.lc];		//少了判断，不确定有没有影响
		}
		else{
			 papdu.le = buf[ISO7816.OFFSET_LC];
			 papdu.lc = 0;
		}
//		ISOException.throwIt(papdu.le);
		
		boolean rc = handleEvent();
		
		//步骤4:判断是否需要返回数据，并设置apdu缓冲区	
		if(rc && papdu.le != 0){
			//指令的执行结果放在pdata中，现在将pdata拷到缓冲区buf
			Util.arrayCopyNonAtomic(papdu.pdata, (short)0, buf, (short)0, papdu.le);
			apdu.setOutgoingAndSend((short)0, papdu.le);
		}
		else if(!rc){
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		}
	}

	/*
	 * 功能：对命令的分析和处理
	 * 参数：无
	 * 返回：是否成功处理了命令
	 */
	private boolean handleEvent(){
		if(papdu.ins==condef.INS_TEST){ //(lxs)
			T = new Test();
			return T.test(papdu, keyfile); 
		}
		switch(papdu.ins){
			//todo：完成写二进制命令，读二进制命令，写密钥命令
			case condef.INS_CREATE_FILE:		return create_file();
			case condef.INS_WRITE_BIN:			return write_bin();
			case condef.INS_WRITE_KEY:			return write_key();
			case condef.INS_READ_BIN:			return read_bin();
			
			case condef.INS_NIIT_TRANS:			return init();
			case condef.INS_LOAD:				return load();
			case condef.INS_PURCHASE:			return purchase();
			case condef.INS_GET_BALANCE:		return get_balance();
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				return false;
		}
	}
	/*
	 * 功能：创建文件
	 */
	private boolean create_file() {
		switch(papdu.pdata[0]){ 
		//todo:完成创建密钥文件，持卡人基本文件和应用基本文件
		case condef.EP_FILE:        return EP_file();  
		case condef.KEY_FILE:		return Key_file();
		case condef.CARD_FILE:		return CARD_file();
		case condef.PERSON_FILE:	return PERSON_file();
		default: 
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			return false;
		}
	}
	/*
	 * 功能：创建电子钱包文件
	 */
	private boolean EP_file() {
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		/*
		if(papdu.p2 != (byte)0x18){
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}		
		*/
		if(papdu.lc != (byte)0x07) //文件控制信息长度，create_file统一为07 
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		EPfile = new EPFile(keyfile);
		
		return true;
	}	
	
	/*
	 * 创建密钥文件
	 */
	private boolean Key_file(){
		if(papdu.cla != (byte)0x80){
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		/*
		if(papdu.p2 != (byte)0x00){
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		*/
		if(papdu.lc != (byte)0x07){
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);			
		}
		if(keyfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		keyfile = new KeyFile();
		
		return true;
	}
	
	/*
	 * 应用基本文件
	 */
	private boolean CARD_file(){
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		/*
		if(papdu.p2 != (byte)0x16){
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}		
		*/
		if(papdu.lc != (byte)0x07) 
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(cardfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		cardfile = new BinaryFile(papdu.pdata);
		
		return true;
	}
	
	/*
	 * 持卡人基本文件
	 */
	private boolean PERSON_file(){
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		/*
		if(papdu.p2 != (byte)0x17){
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		*/				
		if(papdu.lc != (byte)0x07) 
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(personfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		personfile = new BinaryFile(papdu.pdata);
		
		return true;
	}
	
	/*
	 * 写二进制文件
	 */
	private boolean write_bin(){
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
				
		if(papdu.p1 == 0x16){//写应用基本文件
			cardfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		}
		else if(papdu.p1 == 0x17){//写持卡人基本文件
			personfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		}
		else{
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		return true;
	}	
	
	/*
	 * 读文件
	 */
	private boolean read_bin(){
		if(papdu.cla != (byte)0x00){
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			return false;
		}
		if(papdu.p1 == 0x16){//应用基本文件
			cardfile.read_binary(papdu.p2, papdu.le, papdu.pdata);//读到的文件放在pdata中
		}
		else if(papdu.p1 == 0x17){//持卡人基本文件
			personfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		}
		else{
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return false;
		}		
		
		return true;
	}

	/*
	 * 写密钥文件
	 */
	private boolean write_key(){
		if(keyfile == null)//还没密钥文件
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		//文件标识不正确
		if(papdu.p2 != (byte)0x06 && papdu.p2 != (byte)0x07 && papdu.p2 != (byte)0x08)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
	
		if(papdu.lc == 0 || papdu.lc > 21)//密钥长度不能为0也不能超过21
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(keyfile.recNum >= 3)//文件空间已满
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		
		keyfile.addkey(papdu.p2, papdu.lc, papdu.pdata);
		
		return true;
	}

	/*
	 * 初始化圈存和初始化消费命令
	 */
	private boolean init(){
		if(papdu.p1==0x00){
			return init_load();
		}
		else if(papdu.p1==0x01){
			return init_purchase();
		}
		else{
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return false;
		}
		
	}
	
	/*
	 * 功能：圈存初始化命令的实现
	 */
	private boolean init_load() {
		short num,rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		num = keyfile.findkey(papdu.pdata[0]);
		
		// ISOException.throwIt(num);				//test
		
		if(num == 0x00)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4load(num, papdu.pdata);
		
		if(rc == 2)
			ISOException.throwIt((condef.SW_LOAD_FULL));
		
		papdu.le = (short)0x10;
		//ISOException.throwIt(rc);
		return true;
	}

	/*
	 * 功能：消费初始化的实现
	 */
	private boolean init_purchase(){
		short num,rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		num = keyfile.findkey(papdu.pdata[0]);//根据tag寻找密钥返回密钥的记录号
		
		if(num == 0x00)//表示找不到相应密钥
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4purchase(num, papdu.pdata);//返回0表示成功,返回2表示余额不足
		
		if(rc == 2)
			ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
		
		papdu.le = (short)15;
		
		return true;
	}
	
	/*
	 * 功能：圈存命令的实现
	 */
 	private boolean load() {
		short rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		rc = EPfile.load(papdu.pdata);
		
		if(rc == 1)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_LOAD_FULL);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)4;
		
		return true;
	}	

 	/*
	 * 功能：消费命令的实现
	 */
	private boolean purchase(){
short rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		if(papdu.lc != (short)0x0F)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		//ISOException.throwIt(papdu.lc);
		
		rc = EPfile.purchase(papdu.pdata);
		
		if(rc == 1)//MAC1验证未通过
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)8;//正确是8
		
		return true;
	}
	/*
	 * 功能：余额查询功能的实现
	 */
	private boolean get_balance(){
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		short result;
		byte[] balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);	//余额暂存
		result = EPfile.get_balance(balance);
		
		if(result == (short)0)
			Util.arrayCopyNonAtomic(balance, (short)0, papdu.pdata, (short)0, (short)4);		//余额data[0]~data[3]
		
		papdu.le = (short)0x04;
		
		return true;
	}
}

