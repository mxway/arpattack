// attackDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "common.h"
#include <pcap.h>
#include<vector>
using namespace std;


// CattackDlg 对话框
class CattackDlg : public CDialog
{
// 构造
public:
	CattackDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_ATTACK_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_interfaceLst;
	afx_msg void OnNMDblclkList1(NMHDR *pNMHDR, LRESULT *pResult);
private:
	void GetInterfaceArray(vector<MyNetCard> &interfaceArray);
	void InitListData(vector<MyNetCard> &interfaceArray);
	void GetIp4Str(pcap_addr *address,char *ipAddr, char *netmask);
};
