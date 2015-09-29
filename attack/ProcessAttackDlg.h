#pragma once
#include<string>
#include<pcap.h>
#include<vector>
#include<fstream>
#include "common.h"
using namespace std;

// CProcessAttackDlg 对话框

class CProcessAttackDlg : public CDialog
{
	DECLARE_DYNAMIC(CProcessAttackDlg)

public:
	CProcessAttackDlg(string netCardId,CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CProcessAttackDlg();

// 对话框数据
	enum { IDD = IDD_DIALOG1 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	static DWORD WINAPI CapturePacketFunc(LPVOID lpParameter);
	static DWORD WINAPI SendArpPacket(LPVOID lpParameter);
	static PROTOCOL_TYPE GetProtocolType(const u_char *data,int len);
	static void SendPacket(pcap_t *adHanle,const u_char *requestData,int reqLen);
	
	static unsigned char getRand();
private:
	string m_netCardId;
	pcap_t	*m_adhandle;
	HANDLE m_threadHandle;
	HANDLE m_addHandle;
	bool   m_isRun;
	vector<string> m_ipArray;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnClose();
	afx_msg void OnBnClickedCancel();
};
