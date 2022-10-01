
// PrlSnifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "PrlSniffer.h"
#include "PrlSnifferDlg.h"
#include "afxdialogex.h"


char line[1024] = { 0 };
char content[MAXBYTE] = { 0 };
SOCKET sock;
WSADATA wsd;
char recvBuf[65535] = { 0 };
char temp[65535] = { 0 };
DWORD dwBytesRet;
int pCount = 0;
unsigned int optval = 1;
unsigned char* dataip = nullptr;
unsigned char* datatcp = nullptr;
unsigned char* dataudp = nullptr;
unsigned char* dataicmp = nullptr;

int lentcp, lenudp, lenicmp, lenip;

char TcpFlag[6] = { 'F', 'S', 'R', 'A', 'U' };//定义TCP标志位
void clear()
{
	WSACleanup();
	memset(line, 0, 1024);
	memset(content, 0, MAXBYTE);
	memset(recvBuf, 0, 65535);
	memset(temp, 0, 65535);

	pCount = 0;
	optval = 1;
	dataip = nullptr;
	datatcp = nullptr;
	dataudp = nullptr;
	dataicmp = nullptr;
}

typedef struct ip_hdr//定义IP首部
{
	unsigned char h_verlen;//4位首部长度，4位IP版本号
	unsigned char tos;//8位服务类型TOS
	unsigned short tatal_len;//16位总长度
	unsigned short ident;//16位标示
	unsigned short frag_and_flags;//偏移量和3位标志位
	unsigned char ttl;//8位生存时间TTL
	unsigned char proto;//8位协议（TCP,UDP或其他）
	unsigned short checksum;//16位IP首部检验和
	unsigned int sourceIP;//32位源IP地址
	unsigned int destIP;//32位目的IP地址
}IPHEADER;

typedef struct tsd_hdr//定义TCP伪首部
{
	unsigned long saddr;//源地址
	unsigned long daddr;//目的地址
	char mbz;
	char ptcl;//协议类型
	unsigned short tcpl;//TCP长度
}PSDHEADER;

typedef struct tcp_hdr//定义TCP首部
{
	unsigned short sport;//16位源端口
	unsigned short dport;//16位目的端口
	unsigned int seq;//32位序列号
	unsigned int ack;//32位确认号
	unsigned char lenres;//4位首部长度/6位保留字
	unsigned char flag;//6位标志位
	unsigned short win;//16位窗口大小
	unsigned short sum;//16位检验和
	unsigned short urp;//16位紧急数据偏移量
}TCPHEADER;

typedef struct udp_hdr//定义UDP首部
{
	unsigned short sport;//16位源端口
	unsigned short dport;//16位目的端口
	unsigned short len;//UDP 长度
	unsigned short cksum;//检查和
}UDPHEADER;

typedef struct icmp_hdr//定义ICMP首部
{
	unsigned short sport;
	unsigned short dport;
	unsigned char type;
	unsigned char code;
	unsigned short cksum;
	unsigned short id;
	unsigned short seq;
	unsigned long timestamp;
}ICMPHEADER;


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


// CPrlSnifferDlg 对话框



CPrlSnifferDlg::CPrlSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PRLSNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPrlSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CPrlSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_OK, &CPrlSnifferDlg::OnBnClickedButtonOk)

	ON_BN_CLICKED(IDC_BUTTON_CLEAR, &CPrlSnifferDlg::OnBnClickedButtonClear)
END_MESSAGE_MAP()


// CPrlSnifferDlg 消息处理程序

BOOL CPrlSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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

	




	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CPrlSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CPrlSnifferDlg::OnPaint()
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
HCURSOR CPrlSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CPrlSnifferDlg::OnBnClickedButtonOk()
{

	int cnt;
	char scnt[33];



	
	FILE *r = fopen("log.txt", "r");
	
	
	FILE *f = fopen("log.txt", "w+");
	WSAStartup(MAKEWORD(2, 1), &wsd);
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sock == SOCKET_ERROR)//创建一个原始套接字
	{
		exit(0);
	}
	struct in_addr addr;

	char FAR name[MAXBYTE];
	//gethostname(name, MAXBYTE);
	GetDlgItemTextA(IDC_EDIT_ID, name, MAXBYTE);

	struct hostent FAR* pHostent;
	GetDlgItemTextA(IDC_EDIT_COUNT, scnt,33);


	cnt = atoi(scnt);

	pHostent = (struct hostent*)malloc(sizeof(struct hostent));
	pHostent = gethostbyname(name);
	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(1);//原始套接字没有端口的概念，所以这个值随便设置
	memcpy(&sa.sin_addr, pHostent->h_addr_list[0], pHostent->h_length);//设置本机地址

	bind(sock, (SOCKADDR*)&sa, sizeof(sa));//绑定
	if (WSAGetLastError() == 10013)
	{
		exit(0);
	}

	//设置网卡为混杂模式，也叫泛听模式。可以侦听经过的所有的包。
	WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), nullptr, 0, &dwBytesRet, nullptr, nullptr);

	UDPHEADER * pUdpheader;//UDP头结构体指针
	IPHEADER * pIpheader;//IP头结构体指针
	TCPHEADER * pTcpheader;//TCP头结构体指针
	ICMPHEADER * pIcmpheader;//ICMP头结构体指针
	char szSourceIP[MAX_ADDR_LEN], szDestIP[MAX_ADDR_LEN];//源IP和目的IP
	SOCKADDR_IN saSource, saDest;//源地址结构体，目的地址结构体

	//设置各种头指针
	pIpheader = (IPHEADER*)recvBuf;
	pTcpheader = (TCPHEADER*)(recvBuf + sizeof(IPHEADER));
	pUdpheader = (UDPHEADER*)(recvBuf + sizeof(IPHEADER));
	pIcmpheader = (ICMPHEADER*)(recvBuf + sizeof(IPHEADER));
	int iIphLen = sizeof(unsigned long)*(pIpheader->h_verlen & 0x0f);
	int  i = 0;
	SetDlgItemTextA(IDC_STATUS, "Run...");
	while (1)
	{
		
		memset(recvBuf, 0, sizeof(recvBuf));//清空缓冲区
		recv(sock, recvBuf, sizeof(recvBuf), 0);//接收包

		//获得源地址和目的地址
		saSource.sin_addr.s_addr = pIpheader->sourceIP;
		strncpy(szSourceIP, inet_ntoa(saSource.sin_addr), MAX_ADDR_LEN);
		saDest.sin_addr.s_addr = pIpheader->destIP;
		strncpy(szDestIP, inet_ntoa(saDest.sin_addr), MAX_ADDR_LEN);

		//计算各种包的长度（只有判断是否是该包后才有意义，先计算出来）
		lenip = ntohs(pIpheader->tatal_len);
		lentcp = ntohs(pIpheader->tatal_len) - (sizeof(IPHEADER) + sizeof(TCPHEADER));
		lenudp = ntohs(pIpheader->tatal_len) - (sizeof(IPHEADER) + sizeof(UDPHEADER));
		lenicmp = ntohs(pIpheader->tatal_len) - (sizeof(IPHEADER) + sizeof(ICMPHEADER));


		//判断是否是TCP包
		if (pIpheader->proto == IPPROTO_ICMP && lentcp != 0)
		{
			if (i == cnt) break;

			pCount++;//计数加一
			dataip = (unsigned char *)recvBuf;
			datatcp = (unsigned char *)recvBuf + sizeof(IPHEADER) + sizeof(TCPHEADER);
			fprintf(f, "\n#################数据包[%i]=%d字节数据#############\n", pCount, lentcp);
			fprintf(f, "**********IP协议头部***********\n");
			fprintf(f, "标示：%i\n", ntohs(pIpheader->ident));
			fprintf(f, "总长度：%i\n", ntohs(pIpheader->tatal_len));
			fprintf(f, "偏移量：%i\n", ntohs(pIpheader->frag_and_flags));
			fprintf(f, "生存时间：%d\n", pIpheader->ttl);
			fprintf(f, "服务类型：%d\n", pIpheader->tos);
			fprintf(f, "协议类型：%d\n", pIpheader->proto);
			fprintf(f, "检验和：%i\n", ntohs(pIpheader->checksum));
			fprintf(f, "源IP：%s\n", szSourceIP);
			fprintf(f, "目标IP：%s\n", szDestIP);
			fprintf(f, "**********ICMP协议头部***********\n");
			fprintf(f, "源端口：%i\n", ntohs(pIcmpheader->sport));
			fprintf(f, "目的端口：%i\n", ntohs(pIcmpheader->dport));
			fprintf(f, "类型：%i\n", ntohs(pIcmpheader->type));
			fprintf(f, "代码：%i\n", ntohs(pIcmpheader->code));
			fprintf(f, "检验和：%i\n", ntohs(pIcmpheader->cksum));
			fprintf(f, "编号：%i\n", ntohs(pIcmpheader->id));
			fprintf(f, "序号：%i\n", ntohs(pIcmpheader->seq));
			fprintf(f, "时间：%i\n", ntohs(pIcmpheader->timestamp));

			
			i++;
		}
		if (pIpheader->proto == IPPROTO_TCP && lentcp != 0)
		{
			if (i == cnt) break;

			pCount++;//计数加一
			dataip = (unsigned char *)recvBuf;
			datatcp = (unsigned char *)recvBuf + sizeof(IPHEADER) + sizeof(TCPHEADER);
			fprintf(f, "\n#################数据包[%i]=%d字节数据#############\n", pCount, lentcp);
			fprintf(f, "**********IP协议头部***********\n");	
			fprintf(f, "标示：%i\n", ntohs(pIpheader->ident));		
			fprintf(f, "总长度：%i\n", ntohs(pIpheader->tatal_len));		
			fprintf(f, "偏移量：%i\n", ntohs(pIpheader->frag_and_flags));		
			fprintf(f, "生存时间：%d\n", pIpheader->ttl);	
			fprintf(f, "服务类型：%d\n", pIpheader->tos);
			fprintf(f, "协议类型：%d\n", pIpheader->proto);
			fprintf(f, "检验和：%i\n", ntohs(pIpheader->checksum));
			fprintf(f, "源IP：%s\n", szSourceIP);
			fprintf(f, "目标IP：%s\n", szDestIP);
			fprintf(f, "**********TCP协议头部***********\n");
			fprintf(f, "源端口：%i\n", ntohs(pTcpheader->sport));
			fprintf(f, "目的端口：%i\n", ntohs(pTcpheader->dport));
			fprintf(f,"序列号：%i\n", ntohs(pTcpheader->seq));
			fprintf(f, "应答号：%i\n", ntohs(pTcpheader->ack));
			fprintf(f, "检验和：%i\n", ntohs(pTcpheader->sum));
			fprintf(f, "标志位：");
			unsigned char FlagMask = 1;
			int k;
			//打印标志位
			for (k = 0; k < 6; k++)
			{
				if ((pTcpheader->flag)&FlagMask)
					fprintf(f, "%c", TcpFlag[k]);
				else
					fprintf(f, " ");
				FlagMask = FlagMask << 1;
			}
	
			if (ntohs(pTcpheader->dport) == 80) {
				if(!strncmp((const char *)datatcp, "GET",3) || !strncmp((const char *)datatcp, "POST",4))
					fprintf(f,"\n%s\n", datatcp);
				
			}
			i++;
		}
		if (pIpheader->proto == IPPROTO_UDP && lentcp != 0)
		{
			if (i == cnt) break;

			pCount++;//计数加一
			dataip = (unsigned char *)recvBuf;
			datatcp = (unsigned char *)recvBuf + sizeof(IPHEADER) + sizeof(TCPHEADER);
			fprintf(f, "\n#################数据包[%i]=%d字节数据#############\n", pCount, lentcp);	
			fprintf(f, "**********IP协议头部***********\n");
			fprintf(f, "标示：%i\n", ntohs(pIpheader->ident));
			fprintf(f, "总长度：%i\n", ntohs(pIpheader->tatal_len));
			fprintf(f, "偏移量：%i\n", ntohs(pIpheader->frag_and_flags));
			fprintf(f, "生存时间：%d\n", pIpheader->ttl);
			fprintf(f, "服务类型：%d\n", pIpheader->tos);
			fprintf(f, "协议类型：%d\n", pIpheader->proto);
			fprintf(f,  "检验和：%i\n", ntohs(pIpheader->checksum));	
			fprintf(f, "源IP：%s\n", szSourceIP);
			fprintf(f, "目标IP：%s\n", szDestIP);
			fprintf(f, "**********UDP协议头部***********\n");
			fprintf(f, "源端口：%i\n", ntohs(pUdpheader->sport));
			fprintf(f, "目的端口：%i\n", ntohs(pUdpheader->dport));
			fprintf(f, "长度：%i\n", ntohs(pUdpheader->len));
			fprintf(f, "检验和：%i\n", ntohs(pUdpheader->cksum));


			i++;
		}


		

	}
	fclose(f);
	
	
int count = 0;
char flag;
while (!feof(r))
{
	flag = fgetc(r);
	if (flag == '\n')
		count++;
}
rewind(r);
int k = 0;
	while (!feof(r))
	{
	  
		fgets(line, 1024, r);

			GetDlgItemTextA(IDC_EDIT_INFO, content,strlen(content));
			strcat(content, "\r\n");
			if (k < count) {
				strcat(content, line);
				strcat(content, "\r\n");
			}
			SetDlgItemTextA(IDC_EDIT_INFO, content);
			k++;
	}


	fclose(r);
	clear();
	SetDlgItemTextA(IDC_STATUS, "Done");
}






void CPrlSnifferDlg::OnBnClickedButtonClear()
{
	// TODO: 在此添加控件通知处理程序代码
	SetDlgItemTextA(IDC_EDIT_INFO, "Done");
}


