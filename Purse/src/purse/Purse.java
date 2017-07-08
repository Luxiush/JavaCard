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
	
	//�ļ�ϵͳ
	private KeyFile keyfile;            //��Կ�ļ�
	private BinaryFile cardfile;       //Ӧ�û����ļ�
	private BinaryFile personfile;     //�ֿ��˻����ļ�
	private EPFile EPfile;              //����Ǯ���ļ�
	
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
		//����1:ȡAPDU�������������ò���֮�����½�����
		byte[] buf = apdu.getBuffer();//getBuffer���ص��ǻ����������ã�ͨ��buf����ֱ���޸Ļ�����
		//����2��ȡAPDU�����������ݷŵ�����papdu
		apdu.setIncomingAndReceive(); 
		papdu.cla = buf[ISO7816.OFFSET_CLA];
		papdu.ins = buf[ISO7816.OFFSET_INS];
		papdu.p1 = buf[ISO7816.OFFSET_P1];
		papdu.p2 = buf[ISO7816.OFFSET_P2];		
		
		//����3���ж�����APDU�Ƿ�������ݶΣ����������ȡ���ݳ��ȣ�����le��ֵ�����򣬼�����Ҫlc��data�����ȡ������ԭ��lcʵ������le
		if(papdu.APDUContainData()){
			papdu.lc = buf[ISO7816.OFFSET_LC];
			Util.arrayCopyNonAtomic(buf, (short)ISO7816.OFFSET_CDATA, papdu.pdata, (short)0, papdu.lc);
			papdu.le = buf[ISO7816.OFFSET_CDATA+papdu.lc];		//�����жϣ���ȷ����û��Ӱ��
		}
		else{
			 papdu.le = buf[ISO7816.OFFSET_LC];
			 papdu.lc = 0;
		}
//		ISOException.throwIt(papdu.le);
		
		boolean rc = handleEvent();
		
		//����4:�ж��Ƿ���Ҫ�������ݣ�������apdu������	
		if(rc && papdu.le != 0){
			//ָ���ִ�н������pdata�У����ڽ�pdata����������buf
			Util.arrayCopyNonAtomic(papdu.pdata, (short)0, buf, (short)0, papdu.le);
			apdu.setOutgoingAndSend((short)0, papdu.le);
		}
		else if(!rc){
			ISOException.throwIt(ISO7816.SW_UNKNOWN);
		}
	}

	/*
	 * ���ܣ�������ķ����ʹ���
	 * ��������
	 * ���أ��Ƿ�ɹ�����������
	 */
	private boolean handleEvent(){
		if(papdu.ins==condef.INS_TEST){ //(lxs)
			T = new Test();
			return T.test(papdu, keyfile); 
		}
		switch(papdu.ins){
			//todo�����д��������������������д��Կ����
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
	 * ���ܣ������ļ�
	 */
	private boolean create_file() {
		switch(papdu.pdata[0]){ 
		//todo:��ɴ�����Կ�ļ����ֿ��˻����ļ���Ӧ�û����ļ�
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
	 * ���ܣ���������Ǯ���ļ�
	 */
	private boolean EP_file() {
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		/*
		if(papdu.p2 != (byte)0x18){
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}		
		*/
		if(papdu.lc != (byte)0x07) //�ļ�������Ϣ���ȣ�create_fileͳһΪ07 
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		EPfile = new EPFile(keyfile);
		
		return true;
	}	
	
	/*
	 * ������Կ�ļ�
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
	 * Ӧ�û����ļ�
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
	 * �ֿ��˻����ļ�
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
	 * д�������ļ�
	 */
	private boolean write_bin(){
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
				
		if(papdu.p1 == 0x16){//дӦ�û����ļ�
			cardfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		}
		else if(papdu.p1 == 0x17){//д�ֿ��˻����ļ�
			personfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		}
		else{
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		return true;
	}	
	
	/*
	 * ���ļ�
	 */
	private boolean read_bin(){
		if(papdu.cla != (byte)0x00){
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			return false;
		}
		if(papdu.p1 == 0x16){//Ӧ�û����ļ�
			cardfile.read_binary(papdu.p2, papdu.le, papdu.pdata);//�������ļ�����pdata��
		}
		else if(papdu.p1 == 0x17){//�ֿ��˻����ļ�
			personfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		}
		else{
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return false;
		}		
		
		return true;
	}

	/*
	 * д��Կ�ļ�
	 */
	private boolean write_key(){
		if(keyfile == null)//��û��Կ�ļ�
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		//�ļ���ʶ����ȷ
		if(papdu.p2 != (byte)0x06 && papdu.p2 != (byte)0x07 && papdu.p2 != (byte)0x08)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
	
		if(papdu.lc == 0 || papdu.lc > 21)//��Կ���Ȳ���Ϊ0Ҳ���ܳ���21
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(keyfile.recNum >= 3)//�ļ��ռ�����
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		
		keyfile.addkey(papdu.p2, papdu.lc, papdu.pdata);
		
		return true;
	}

	/*
	 * ��ʼ��Ȧ��ͳ�ʼ����������
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
	 * ���ܣ�Ȧ���ʼ�������ʵ��
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
	 * ���ܣ����ѳ�ʼ����ʵ��
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
		
		num = keyfile.findkey(papdu.pdata[0]);//����tagѰ����Կ������Կ�ļ�¼��
		
		if(num == 0x00)//��ʾ�Ҳ�����Ӧ��Կ
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4purchase(num, papdu.pdata);//����0��ʾ�ɹ�,����2��ʾ����
		
		if(rc == 2)
			ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
		
		papdu.le = (short)15;
		
		return true;
	}
	
	/*
	 * ���ܣ�Ȧ�������ʵ��
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
	 * ���ܣ����������ʵ��
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
		
		if(rc == 1)//MAC1��֤δͨ��
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_BALANCE_NOT_ENOUGH);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)8;//��ȷ��8
		
		return true;
	}
	/*
	 * ���ܣ�����ѯ���ܵ�ʵ��
	 */
	private boolean get_balance(){
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		short result;
		byte[] balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);	//����ݴ�
		result = EPfile.get_balance(balance);
		
		if(result == (short)0)
			Util.arrayCopyNonAtomic(balance, (short)0, papdu.pdata, (short)0, (short)4);		//���data[0]~data[3]
		
		papdu.le = (short)0x04;
		
		return true;
	}
}

