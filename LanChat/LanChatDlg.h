
// LanChatDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"


// CLanChatDlg 对话框
class CLanChatDlg : public CDialogEx
{
// 构造
public:
	CLanChatDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_LANCHAT_DIALOG };
#endif

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
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLbnSelchangeList1();
	afx_msg void OnEnChangeEdit1();
//	afx_msg void OnEnChangeEdit2();
	CListBox lbChatContent;
	SOCKET sRaw;
	static DWORD WINAPI RecvProc(LPVOID lpVoid);
	static CString IP;
	CIPAddressCtrl ipRecevier;
	bool flag;
	CString strIP;
};
