
// LanChatDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "LanChat.h"
#include "LanChatDlg.h"
#include "afxdialogex.h"
//#include "InitSock.h"

#include "initsock.h"
#include "protoinfo.h" 

#include <stdio.h>
#include <mstcpip.h>

#pragma comment(lib, "Advapi32.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//CInitSock initSock;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CLanChatDlg 对话框



CLanChatDlg::CLanChatDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_LANCHAT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CLanChatDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, lbChatContent);
	DDX_Control(pDX, IDC_IPADDRESS1, ipRecevier);
}

BEGIN_MESSAGE_MAP(CLanChatDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CLanChatDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CLanChatDlg::OnBnClickedCancel)
	ON_NOTIFY(IPN_FIELDCHANGED, IDC_IPADDRESS1, &CLanChatDlg::OnIpnFieldchangedIpaddress1)
//	ON_EN_CHANGE(IDC_EDIT2, &CLanChatDlg::OnEnChangeEdit2)
END_MESSAGE_MAP()


// CLanChatDlg 消息处理程序

BOOL CLanChatDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	flag = 0;
	
	// 创建原始套节字
	sRaw = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	// 获取本地IP地址
	char szHostName[56];
	SOCKADDR_IN addr_in;
	struct  hostent *pHost;
	gethostname(szHostName, 56);
	if ((pHost = gethostbyname((char*)szHostName)) == NULL)
		return FALSE;

	// 在调用ioctl之前，套节字必须绑定
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(6666);
	memcpy(&addr_in.sin_addr.S_un.S_addr, pHost->h_addr_list[2], pHost->h_length);

	lbChatContent.AddString(_T(" bind start\n "));
	printf(" Binding to interface : %s \n", ::inet_ntoa(addr_in.sin_addr));
	if (bind(sRaw, (PSOCKADDR)&addr_in, sizeof(addr_in)) == SOCKET_ERROR) {
		lbChatContent.AddString(_T(" bind failed\n "));
		printf("bind failed\n");
		return FALSE;
	}

	// 设置SIO_RCVALL控制代码，以便接收所有的IP包	
	DWORD dwValue = 1;
	if (ioctlsocket(sRaw, SIO_RCVALL, &dwValue) != 0) {
		printf("ioctlsocket failed\n");
		return FALSE;
	}

	::CreateThread(nullptr, 0, RecvProc, (LPVOID)this, 0, nullptr);   //创建接收线程


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CLanChatDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CLanChatDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CLanChatDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CLanChatDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	//CDialogEx::OnOK();
	
	UpdateData(TRUE);

	//将IPAddressCtrl中的IP地址获得并转换成CString型 
	unsigned char *pIP;
	//CString strIP; //have been tranfer to .h
	DWORD dwIP;
	ipRecevier.GetAddress(dwIP);   //读取输入的ip
	pIP = (unsigned char*)&dwIP;   //ip格式转换（DWORD->char*）
	strIP.Format(_T("%d.%d.%d.%d"),   //ip格式转换（char*->CString）
		(dwIP >> 24) & 0xff,
		(dwIP >> 16) & 0xff,
		(dwIP >> 8) & 0xff,
		dwIP & 0xff);
	char * chrIP;
	USES_CONVERSION; //cstring 转char*
	chrIP = T2A(strIP);


	if (!flag) {     //初次发送消息时与指定ip建立连接
		sockaddr_in servAddr;
		servAddr.sin_family = AF_INET;
		servAddr.sin_port = htons(4567);
		servAddr.sin_addr.S_un.S_addr = inet_addr(chrIP);

		lbChatContent.AddString(_T(" Listen: ") + strIP + _T(" turn on\r\n"));
		flag = 1;
	}
	else { 
		lbChatContent.AddString(_T(" Listen: ") + strIP + _T(" turn off\r\n")); 
		flag = 0; 
	}

	UpdateData(FALSE);
	//lbChatContent->ReplaceSel(s + "/r/n");

}

void DecodeTCPPacket(CLanChatDlg* vm, char *pData)
{
	TCPHeader *pTCPHdr = (TCPHeader *)pData;
	int nHeaderLen = (pTCPHdr->dataoffset >> 4 & 0xf) * sizeof(ULONG);

	USES_CONVERSION;
	CString protocol;
	// 下面还可以根据目的端口号进一步解析应用层协议
	switch (::ntohs(pTCPHdr->destinationPort))
	{
	case 21:
		protocol = A2T("FTP");
		break;
	case 80:
	case 8000:
	case 8080:
		protocol = A2T("HTTP");
		break;
	case 443:
		protocol = A2T("HTTPS");
		break;
	}

	
	CString ptp;
	ptp.Format(_T(" Port: %d -> %d \n"), ntohs(pTCPHdr->sourcePort), ntohs(pTCPHdr->destinationPort));
	CString msg = A2T(pData + nHeaderLen);
	//vm->lbChatContent.AddString(_T("Port: ") + ntohs(pTCPHdr->sourcePort) + _T(" -> ") + _T("\r\n"));
	vm->lbChatContent.AddString(ptp);
	vm->lbChatContent.AddString(protocol);
	vm->lbChatContent.AddString(_T(" message: ") + msg + _T("\r\n"));
}

void DecodeUDPPacket(CLanChatDlg* vm, char *pData)
{
	UDPHeader *pUDPHdr = (UDPHeader *)pData;

	USES_CONVERSION;
	CString protocol;
	switch (::ntohs(pUDPHdr->sourcePort))
	{
	case 21:
		protocol = A2T("FTP");
		break;
	case 80:
	case 8000:
	case 8080:
		protocol = A2T("HTTP");
		break;
	case 443:
		protocol = A2T("HTTPS");
		break;
	}

	CString ptp;
	ptp.Format(_T(" Port: %d -> %d \n"), ntohs(pUDPHdr->sourcePort), ntohs(pUDPHdr->destinationPort));
	CString msg = A2T(pData + +sizeof(struct _UDPHeader));
	//vm->lbChatContent.AddString(_T("Port: ") + ntohs(pTCPHdr->sourcePort) + _T(" -> ") + _T("\r\n"));
	vm->lbChatContent.AddString(ptp);
	vm->lbChatContent.AddString(protocol);
	vm->lbChatContent.AddString(_T(" message: ") + msg + _T("\r\n"));
}


void DecodeIPPacket(CLanChatDlg* vm, char *pData)
{
	IPHeader *pIPHdr = (IPHeader*)pData;
	in_addr source, dest;
	char szSourceIp[32], szDestIp[32];

	// 从IP头中取出源IP地址和目的IP地址
	source.S_un.S_addr = pIPHdr->ipSource;
	dest.S_un.S_addr = pIPHdr->ipDestination;
	strcpy_s(szSourceIp, ::inet_ntoa(source));
	strcpy_s(szDestIp, ::inet_ntoa(dest));

	

	USES_CONVERSION;
	//CString iti;
	//iti.Format(_T("	%s -> %s \n"), szSourceIp, szDestIp);
	CString sourceIP = A2T(szSourceIp);
	CString destIP = A2T(szDestIp);
	if (vm->strIP != _T("0.0.0.0") && vm->strIP != sourceIP && vm->strIP != destIP) return;
	vm->lbChatContent.AddString(_T("\n\n-------------------------------\n"));
	vm->lbChatContent.AddString(_T("IP: ") + sourceIP + _T(" -> ") + destIP + _T("\r\n"));

	// IP头长度
	int nHeaderLen = (pIPHdr->iphVerLen & 0xf) * sizeof(ULONG);

	switch (pIPHdr->ipProtocol)
	{
	case IPPROTO_TCP: // TCP协议
		vm->lbChatContent.AddString(_T("TCP\r\n"));
		DecodeTCPPacket(vm, pData + nHeaderLen);
		break;
	case IPPROTO_UDP:
		vm->lbChatContent.AddString(_T("UDP\r\n"));
		DecodeUDPPacket(vm, pData + nHeaderLen);
		break;
	case IPPROTO_ICMP:
		vm->lbChatContent.AddString(_T("ICMP\r\n"));
		break;
	default:
		vm->lbChatContent.AddString(_T("IP\r\n"));
	}
}

DWORD WINAPI  CLanChatDlg::RecvProc(LPVOID lpVoid) {   //建立连接之后创建线程用于接受消息
	CLanChatDlg* vm = (CLanChatDlg*)lpVoid;    //传递类变量

	// 开始接收封包
	char buff[1024];
	int nRet;
	while (TRUE)
	{
		if (vm->flag) {
			nRet = ::recv(vm->sRaw, buff, 1024, 0);
			if (nRet > 0)
			{
				DecodeIPPacket(vm, buff);
			}
		}
	}
	closesocket(vm->sRaw);

	return 0;
}

void CLanChatDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	::closesocket(sRaw);
	CDialogEx::OnCancel();
}


void CLanChatDlg::OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}


void CLanChatDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


//void CLanChatDlg::OnEnChangeEdit2()
//{
//	// TODO:  如果该控件是 RICHEDIT 控件，它将不
//	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
//	// 函数并调用 CRichEditCtrl().SetEventMask()，
//	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。
//
//	// TODO:  在此添加控件通知处理程序代码
//}

