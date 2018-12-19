#include "rip.h"

TRtEntry *g_pstRouteEntry = NULL;
TRtEntry *temp_RouteEntry = NULL;
TRtEntry *cur_RouteEntry = NULL;

TRipPkt recvPacket,send_rip_pkt;
struct RouteEntry lcRtTable;
int lcRtTableLen = 0;
struct sockaddr_in localSockAddr,sendSockAddr,recvSockAddr;
int sock, sockzb;
char *pcLocalAddr[10]={};//存储本地接口ip地址
unsigned int pcLocalAddrMask[10]={};
char *pcLocalName[10]={};//存储本地接口的接口名
int lc_ip_size = 0;
char *prtstr[3];

//封装request包
void requestpkt_Encapsulate()
{
	printf("requestpkt_Encapsulate-------------------------------------------------------\n");
	send_rip_pkt.ucCommand = 1;
	send_rip_pkt.ucVersion = 2;
	send_rip_pkt.usZero    = 0;
    //send_rip_pkt.RipEntries[0].usFamily = 0;
    send_rip_pkt.RipEntries[0].uiMetric = htonl(16);
}


/*****************************************************
*Func Name:    rippacket_Receive  
*Description:  接收rip报文
*Input:        
*	 
*Output: 
*
*Ret  ：
*
*******************************************************/
void rippacket_Receive()
{
	printf("rippacket_Receive-------------------------------------------------------\n");
	int length;
	unsigned int SockAddrLen = sizeof(struct sockaddr_in);
	while(1)
	{
		//返回接收到的包的长度
		length=recvfrom(sock,&recvPacket,sizeof(recvPacket),0,(struct sockaddr*)&recvSockAddr,&SockAddrLen);
		printf("recv %d byte packet\n", length);
		//接收rip报文   存储接收源ip地址
		//判断command类型，request 或 response
		// if(recvSockAddr.sin_addr.s_addr == localIP.s_addr)      
	        // continue;
		
		//包的合法性检查
	    if((length-4)%sizeof(struct RipEntry) != 0)
	        continue;
		//检查包头
	    if(recvPacket.ucVersion != 2 || recvPacket.usZero != 0)   
	        continue;
		//分别处理
		if(recvPacket.ucCommand == RIP_REQUEST)
		{
			//request_Handle(recvSockAddr.sin_addr);
			rippacket_Send(recvSockAddr.sin_addr);
		}
		else if(recvPacket.ucCommand == RIP_RESPONSE)
		{
			response_Handle(recvSockAddr.sin_addr,length);
		}
		else
		{
			printf("command invalid.\n");
        	continue;
		}
		//接收到的信息存储到全局变量里，方便request_Handle和response_Handle处理	
	}
}


/*****************************************************
*Func Name:    rippacket_Send  
*Description:  向接收源发送响应报文
*Input:        
*	  1.stSourceIp    ：接收源的ip地址，用于发送目的ip设置
*Output: 
*
*Ret  ：
*
*******************************************************/
void rippacket_Send(struct in_addr stSourceIp)
{
	printf("rippacket_Send-------------------------------------------------------\n");
	printf("            Send response packet from %s ", pcLocalAddr);
	printf("to %s\n", inet_ntoa(stSourceIp));
	//创建socket
	int sockdb = socket(AF_INET,SOCK_DGRAM,0);
	if (-1 == sockdb)
	{
		printf("dbsocket send fail\n");
		return ;
	}
	///*防止绑定地址冲突，仅供参考
	//设置地址重用
	int  iReUseddr = 1;
	if (setsockopt(sockdb,SOL_SOCKET ,SO_REUSEADDR,(const char*)&iReUseddr,sizeof(iReUseddr))<0)
	{
		perror("setsockopt\n");
		return ;
	}
	//设置端口重用
	int  iReUsePort = 1;
	if (setsockopt(sockdb,SOL_SOCKET ,SO_REUSEPORT,(const char*)&iReUsePort,sizeof(iReUsePort))<0)
	{
		perror("setsockopt\n");
		return ;
	}

	//本机ip
	struct sockaddr_in myaddr;
	memset(&myaddr,0,sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_port = htons(520);
	struct in_addr tmplcip,tmp_addr;
	int i=0;
	for(;i<lc_ip_size;i++)
	{
		inet_pton(AF_INET, pcLocalAddr[i], (void *)&tmplcip);
		tmp_addr.s_addr = pcLocalAddrMask[i] & tmplcip.s_addr;
		if(tmp_addr.s_addr == (pcLocalAddrMask[i] & stSourceIp.s_addr))
		{
			myaddr.sin_addr.s_addr = tmplcip.s_addr;
			break;
		}
	}
	if(i == lc_ip_size)
	{
		return;
	}
	//创建并绑定socket
	int bindret = bind(sockdb,(struct sockaddr *)(&myaddr),sizeof(struct sockaddr));
	if (-1 == bindret)
	{
		perror("dbbind send fail\n");
		close(sockdb);
		return ;
	}

	//发送stSourceIp
	struct sockaddr_in toaddr;
	memset(&toaddr,0,sizeof(toaddr));
	toaddr.sin_family = AF_INET;
	toaddr.sin_port = htons(520);
	toaddr.sin_addr = stSourceIp;

	int sendlen = 0;
	for(cur_RouteEntry=g_pstRouteEntry->pstNext;cur_RouteEntry!=NULL;cur_RouteEntry=cur_RouteEntry->pstNext)
	{
		if(cur_RouteEntry->stNexthop.s_addr == stSourceIp.s_addr)
		{
			continue;
		}
		else if(cur_RouteEntry->stIpPrefix.s_addr == (myaddr.sin_addr.s_addr & cur_RouteEntry->uiPrefixLen))
		{
			continue;
		}
		else
		{
			send_rip_pkt.RipEntries[sendlen].usFamily		=htons(AF_INET);
			send_rip_pkt.RipEntries[sendlen].usTag			=0;
			send_rip_pkt.RipEntries[sendlen].stAddr			=cur_RouteEntry->stIpPrefix;
			send_rip_pkt.RipEntries[sendlen].stPrefixLen.s_addr	=cur_RouteEntry->uiPrefixLen;
			send_rip_pkt.RipEntries[sendlen].stNexthop		=cur_RouteEntry->stNexthop;
			send_rip_pkt.RipEntries[sendlen].uiMetric		=cur_RouteEntry->uiMetric;
			sendlen ++;
		}
	}

	//判断sendto是否成功
	int a = sendto(sockdb,&send_rip_pkt,4+sendlen*sizeof(TRipEntry),0,(struct sockaddr*)&toaddr,sizeof(struct sockaddr_in));
	printf("rippacket_Send       sendto length is %d\n", a);
	if(a < 0)
	{
		printf("rippacket_Send      sendto err\n");
		printf("rippacket_Send  errno:%d\n",errno);
		
	}
	close(sockdb);
	return;	
}

/*****************************************************
*Func Name:    rippacket_Multicast  
*Description:  组播请求报文
*Input:        
*	  1.pcLocalAddr   ：本地ip地址
*Output: 
*
*Ret  ：
*
*******************************************************/
void rippacket_Multicast(char *pcLocalAddr,int pkt_len)
{
	printf("rippacket_Multicast-------------------------------------------------------\n");
	printf("    Multicast request packet from %s\n", pcLocalAddr);
	sockzb = socket(AF_INET,SOCK_DGRAM,0);
	if (-1 == sockzb)
	{
		printf("zbsocket fail\n");
		return ;
	}
	///*防止绑定地址冲突，仅供参考
	//设置地址重用
	int iReUseddr = 1;
	if (setsockopt(sockzb,SOL_SOCKET ,SO_REUSEADDR,(const char*)&iReUseddr,sizeof(iReUseddr))<0)
	{
		perror("setsockopt\n");
		return ;
	}
	//设置端口重用
	int iReUsePort = 1;
	if (setsockopt(sockzb,SOL_SOCKET ,SO_REUSEPORT,(const char*)&iReUsePort,sizeof(iReUsePort))<0)
	{
		perror("setsockopt\n");
		return ;
	}
	//把本地地址加入到组播中 	
	
	struct ip_mreq mreq;
	memset(&mreq,0,sizeof(mreq));
	inet_pton(AF_INET, RIP_GROUP, (void *)&mreq.imr_multiaddr);
	inet_pton(AF_INET, pcLocalAddr, (void *)&mreq.imr_interface);
	setsockopt (sockzb, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	
	///*
	//防止组播回环的参考代码	
	
	//int iSockfd;//仅是定义，需自己创建socket
	#if 1
	//0 禁止回环  1开启回环 
	int loop = 0;
	int err = setsockopt(sockzb,IPPROTO_IP, IP_MULTICAST_LOOP,&loop, sizeof(loop));
	if(err < 0)
	{
		perror("setsockopt():IP_MULTICAST_LOOP");
	}
	#endif

	//本机ip
	struct sockaddr_in myaddr;
	memset(&myaddr,0,sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_port = htons(520);
//	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	inet_pton(AF_INET, pcLocalAddr, (void *)&myaddr.sin_addr);

	//创建并绑定socket
	int bindzb = bind(sockzb,(struct sockaddr *)(&myaddr),sizeof(struct sockaddr));
	if (-1 == bindzb)
	{
		perror("bindzb fail\n");
		close(sockzb);
		return ;
	}

	
	struct sockaddr_in toaddr;
	memset(&toaddr,0,sizeof(toaddr));
	toaddr.sin_family = AF_INET;
	toaddr.sin_port = htons(520);
	inet_pton(AF_INET, RIP_GROUP, (void *)&toaddr.sin_addr.s_addr);
	printf("the size of multcast rippackage is %ld\n",4+pkt_len*sizeof(TRipEntry));
	if(0>sendto(sockzb,&send_rip_pkt,4+pkt_len*sizeof(TRipEntry),0,(struct sockaddr*)&toaddr,sizeof(struct sockaddr_in)))
	{
		printf("rippacket_Multicast  sendto err\n");
		printf("rippacket_Multicast  errno:%d\n",errno);
	}
	//发送
	close(sockzb);
	return;
}

/*****************************************************
*Func Name:    request_Handle  
*Description:  响应request报文
*Input:        
*	  1.stSourceIp   ：接收源的ip地址
*Output: 
*
*Ret  ：
*
*******************************************************/
void request_Handle(struct in_addr stSourceIp)
{
	//处理request报文
	//遵循水平分裂算法
	//回送response报文，command置为RIP_RESPONSE
	return;
}

/*****************************************************
*Func Name:    response_Handle  
*Description:  响应response报文
*Input:        
*	  1.stSourceIp   ：接收源的ip地址
*Output: 
*
*Ret  ：
*
*******************************************************/
void response_Handle(struct in_addr stSourceIp,int length)
{
	printf("response_Handle (update the rip route table)--------------------------------------------------\n");
	printf("This is a response package!----------------------------------------------begin\n");
	unsigned int metric,tmpmc;
	int i;
	struct in_addr tmplcip,tmp_addr;
	TRtEntry *del_RouteEntry;
	for(i = 0; i < (length-4)/sizeof(struct RipEntry); i++)
	{
		metric = ntohl(recvPacket.RipEntries[i].uiMetric);   
        metric++;
        for(cur_RouteEntry=g_pstRouteEntry->pstNext;cur_RouteEntry!=NULL;cur_RouteEntry=cur_RouteEntry->pstNext)
		{
			if(cur_RouteEntry->stNexthop.s_addr == stSourceIp.s_addr)
			{
				cur_RouteEntry->ttl = 0;
			}
		}
        if(metric>=16)
        {
			printf("Here is the delete branch\n");
			temp_RouteEntry = g_pstRouteEntry;
        	for(cur_RouteEntry=g_pstRouteEntry->pstNext;cur_RouteEntry!=NULL;cur_RouteEntry=cur_RouteEntry->pstNext)
			{
				if((cur_RouteEntry->stNexthop.s_addr == stSourceIp.s_addr)&(cur_RouteEntry->stIpPrefix.s_addr == recvPacket.RipEntries[i].stAddr.s_addr))
				{
					temp_RouteEntry->pstNext = cur_RouteEntry->pstNext;
					inet_ntop(AF_INET, &cur_RouteEntry->stIpPrefix, prtstr[0], INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &cur_RouteEntry->uiPrefixLen, prtstr[1], INET_ADDRSTRLEN);
					inet_ntop(AF_INET, &cur_RouteEntry->stNexthop, prtstr[2], INET_ADDRSTRLEN);
					tmpmc = ntohl(cur_RouteEntry->uiMetric);
					if(tmpmc < 16)
					{
						printf("response_Handle     delete RouteEntry\nstIpPrefix:%s\tnetmask:%s\tstNexthop:%s\n",prtstr[0],prtstr[1],prtstr[2]);
						del_RouteEntry = cur_RouteEntry;
						cur_RouteEntry->uiMetric = htonl(16);
						route_SendForward(DelRoute,del_RouteEntry);
						//free(del_RouteEntry);
						del_RouteEntry = NULL;
					}
					break;
				}
				temp_RouteEntry = cur_RouteEntry;
			}
			continue;
			//send route delete

        }
		printf("Here is the trying to update the metric branch\n");
        recvPacket.RipEntries[i].uiMetric = htonl(metric);
		for(cur_RouteEntry=g_pstRouteEntry->pstNext;cur_RouteEntry!=NULL;cur_RouteEntry=cur_RouteEntry->pstNext)
		{
			if(cur_RouteEntry->stIpPrefix.s_addr == recvPacket.RipEntries[i].stAddr.s_addr)
			{
				if(cur_RouteEntry->stNexthop.s_addr == stSourceIp.s_addr)
				{
					cur_RouteEntry->uiMetric = recvPacket.RipEntries[i].uiMetric;
					break;
				}
				if(ntohl(cur_RouteEntry->uiMetric) < ntohl(recvPacket.RipEntries[i].uiMetric))
				{
					cur_RouteEntry->stNexthop = stSourceIp;
					cur_RouteEntry->uiMetric = recvPacket.RipEntries[i].uiMetric;
					break;
				}
				break;
			}
			temp_RouteEntry = cur_RouteEntry;
		}
		if(cur_RouteEntry == NULL)
		{
			printf("Here is the new node branch\n");
			temp_RouteEntry = (TRtEntry *)malloc(sizeof(TRtEntry));
			temp_RouteEntry->pstNext = g_pstRouteEntry->pstNext;
			g_pstRouteEntry->pstNext = temp_RouteEntry;

			temp_RouteEntry->stIpPrefix = recvPacket.RipEntries[i].stAddr;
			temp_RouteEntry->uiPrefixLen = recvPacket.RipEntries[i].stPrefixLen.s_addr;
			temp_RouteEntry->stNexthop = stSourceIp;
			temp_RouteEntry->uiMetric = recvPacket.RipEntries[i].uiMetric;
			temp_RouteEntry->ttl = 0;
			int j=0;
			for(;j<lc_ip_size;j++)
			{
				inet_pton(AF_INET, pcLocalAddr[j], (void *)&tmplcip);
				tmp_addr.s_addr = (pcLocalAddrMask[j] & tmplcip.s_addr);
				if(tmp_addr.s_addr == (pcLocalAddrMask[j] & stSourceIp.s_addr))
				{
					temp_RouteEntry->pcIfname = pcLocalName[j];
					break;
				}
			}
			if(j == lc_ip_size)
			{
				printf("!!!!!!!!!!\n");
				return;
			}
			else
			{
				route_SendForward(AddRoute,temp_RouteEntry);
				break;
			}
		}
	}
	printf("This is a response package!----------------------------------------------end\n");
	return;
}

/*****************************************************
*Func Name:    route_SendForward  
*Description:  响应response报文
*Input:        
*	  1.uiCmd        ：插入命令
*	  2.pstRtEntry   ：路由信息
*Output: 
*
*Ret  ：
*
*******************************************************/
void route_SendForward(unsigned int uiCmd,TRtEntry *pstRtEntry)
{
	unsigned int tmp = pstRtEntry->uiPrefixLen;
	int j = 0;
	for(j=0;tmp!=0;j++)
	{
		tmp = tmp << 1;
	}
	TSockRoute ts;
	ts.uiPrefixLen = tmp;
	ts.stIpPrefix = pstRtEntry->stIpPrefix;
	for(int i = 0;i<lc_ip_size;i++)
	{
		if(pstRtEntry->pcIfname == pcLocalName[i])
		{
			ts.uiIfindex = i;
			break;
		}
	}
	ts.stNexthop = pstRtEntry->stNexthop;
	ts.uiCmd = uiCmd;

	//建立tcp短连接，发送插入、删除路由表项信息到转发引擎
	char *servInetAddr = "127.0.0.1";
	int socketfd = socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in sockaddr;

	memset(&sockaddr,0,sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(800);
	inet_pton(AF_INET,servInetAddr,&sockaddr.sin_addr);
	if((connect(socketfd,(struct sockaddr*)&sockaddr,sizeof(sockaddr))) < 0 )
	{
		printf("connect error %s errno: %d\n",strerror(errno),errno);
		return;
	}
	if((send(socketfd,&ts,sizeof(ts),0)) < 0)
	{
		printf("send mes error: %s errno : %d",strerror(errno),errno);
		return;
	}
	close(socketfd);
	return;
}

void rippacket_Update()
{
	//遍历rip路由表，封装更新报文
	printf("rippacket_Update (gennerate the rip packet which is going to be multcasted)-------------------------------------------------\n");
	//注意水平分裂算法
	int sendlen = 0;
	struct in_addr lcinterfIp,temp;
	for(int i=0;i<lc_ip_size;i++)
    {
    	printf("Here is the enumeration of rip table. Now is No.%d\n",i);
    	memset(send_rip_pkt.RipEntries,0,sizeof(send_rip_pkt.RipEntries));
    	inet_pton(AF_INET, pcLocalAddr[i], (void *)&lcinterfIp);
    	sendlen = 0;
    	for(cur_RouteEntry=g_pstRouteEntry->pstNext;cur_RouteEntry!=NULL;cur_RouteEntry=cur_RouteEntry->pstNext)
		{
			if(cur_RouteEntry->stIpPrefix.s_addr == (lcinterfIp.s_addr & cur_RouteEntry->uiPrefixLen))
			{
				continue;
			}
			else
			{
				send_rip_pkt.RipEntries[sendlen].usFamily		=htons(AF_INET);
				send_rip_pkt.RipEntries[sendlen].usTag			=0;
				send_rip_pkt.RipEntries[sendlen].stAddr			=cur_RouteEntry->stIpPrefix;
 				send_rip_pkt.RipEntries[sendlen].stPrefixLen.s_addr	=cur_RouteEntry->uiPrefixLen;
				send_rip_pkt.RipEntries[sendlen].stNexthop		=cur_RouteEntry->stNexthop;
				send_rip_pkt.RipEntries[sendlen].uiMetric		=cur_RouteEntry->uiMetric;
				sendlen ++;
			}
		}
		rippacket_Multicast(pcLocalAddr[i],sendlen);
    }
}

void *update_thread()
{
	TRtEntry *del_RouteEntry;
	printf("*update_thread()--------------------------------------------------\n");
	while (1)
	{
		sleep(5);
		// 这里的顺序真的对吗？
		for(cur_RouteEntry=g_pstRouteEntry->pstNext;cur_RouteEntry!=NULL;cur_RouteEntry=cur_RouteEntry->pstNext)
		{
			inet_ntop(AF_INET, &cur_RouteEntry->stIpPrefix, prtstr[0], INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &cur_RouteEntry->uiPrefixLen, prtstr[1], INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &cur_RouteEntry->stNexthop, prtstr[2], INET_ADDRSTRLEN);
			printf("update_thread      show RouteEntry\nstIpPrefix:%s\tnetmask:%s\tstNexthop:%smetric%d\n",prtstr[0],prtstr[1],prtstr[2],ntohl(cur_RouteEntry->uiMetric));
		}
		rippacket_Update();
		temp_RouteEntry = g_pstRouteEntry;
		for(cur_RouteEntry=g_pstRouteEntry->pstNext;cur_RouteEntry!=NULL;cur_RouteEntry=cur_RouteEntry->pstNext)
		{
			if(cur_RouteEntry->uiMetric != htonl(1))
			{
				cur_RouteEntry->ttl ++;
				if(cur_RouteEntry->ttl>6)
				{
					temp_RouteEntry->pstNext = cur_RouteEntry->pstNext;
					if(ntohl(cur_RouteEntry->uiMetric) < 16)
					{
						inet_ntop(AF_INET, &cur_RouteEntry->stIpPrefix, prtstr[0], INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &cur_RouteEntry->uiPrefixLen, prtstr[1], INET_ADDRSTRLEN);
						inet_ntop(AF_INET, &cur_RouteEntry->stNexthop, prtstr[2], INET_ADDRSTRLEN);
						printf("update_thread      delete RouteEntry\nstIpPrefix:%s\tnetmask:%s\tstNexthop:%s\n",prtstr[0],prtstr[1],prtstr[2]);
						del_RouteEntry = cur_RouteEntry;
						cur_RouteEntry->uiMetric = htonl(16);
						route_SendForward(DelRoute,del_RouteEntry);
						//free(del_RouteEntry);
						del_RouteEntry = NULL;
					}
				}
				else
				{
					temp_RouteEntry = cur_RouteEntry;
				}
			}
			
			if(cur_RouteEntry == NULL)
			{
				printf("null");
			}
		}
	}
}

void ripdaemon_Start()
{
	prtstr[0] = (char *)malloc(sizeof(INET_ADDRSTRLEN));
	prtstr[1] = (char *)malloc(sizeof(INET_ADDRSTRLEN));
	prtstr[2] = (char *)malloc(sizeof(INET_ADDRSTRLEN));
//---------------------------------------------------------------------------------------------------------------------
//单播socket设置
	printf("ripdaemon_Start-------------------------------------------------\n");
	sock = socket(AF_INET,SOCK_DGRAM,0);
	if (-1 == sock)
	{
		printf("rcsocket fail\n");
		return ;
	}
	///*防止绑定地址冲突，仅供参考
	//设置地址重用
	int  iReUseddr = 1;
	if (setsockopt(sock,SOL_SOCKET ,SO_REUSEADDR,(const char*)&iReUseddr,sizeof(iReUseddr))<0)
	{
		perror("setsockopt\n");
		return ;
	}
	//设置端口重用
	int  iReUsePort = 1;
	if (setsockopt(sock,SOL_SOCKET ,SO_REUSEPORT,(const char*)&iReUsePort,sizeof(iReUsePort))<0)
	{
		perror("setsockopt\n");
		return ;
	}
	//把本地地址加入到组播中 	
	struct ip_mreq mreq;
	inet_pton(AF_INET, RIP_GROUP, (void *)&mreq.imr_multiaddr);
	for(int i=0;i<lc_ip_size;i++)
	{
		inet_pton(AF_INET, pcLocalAddr[i], (void *)&mreq.imr_interface);
		setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq));
	}

	//本机ip
	struct sockaddr_in myaddr;
	memset(&myaddr,0,sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_port = htons(520);
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	//创建并绑定socket
	int bindret = bind(sock,(struct sockaddr *)(&myaddr),sizeof(struct sockaddr));
	if (-1 == bindret)
	{
		perror("bindrc fail\n");
		close(sock);
		return ;
	}
//---------------------------------------------------------------------------------------------------------------------


//---------------------------------------------------------------------------------------------------------------------
	//组播socket设置！！！
	//组播socket设置！！！
//------------------------------------------------------------------------------------------------------------------------

	//创建更新线程，30s更新一次,向组播地址更新Update包
	// struct timeval interval;
	// struct itimerval timer;
	// //设置时间间隔为10秒
	// interval.tv_sec = 3;
	// interval.tv_usec = 0;//微秒

	// timer.it_interval = interval;
	// timer.it_value = interval;

	// setitimer(ITIMER_REAL, &timer, NULL);//让它产生SIGVTALRM信号
	// signal(SIGALRM, rippacket_Update);//为SIGVTALRM注册信号处理函数

	//封装请求报文，并组播
    requestpkt_Encapsulate();
    printf("The size of package is %d\n",lc_ip_size);
    for(int i=0;i<lc_ip_size;i++)
    {
    	rippacket_Multicast(pcLocalAddr[i],1);
    }
    send_rip_pkt.ucCommand = 2;
    
	pthread_t th_id;
	if(pthread_create(&th_id,NULL,update_thread,NULL) < 0)
	{
		return;
	}

	//接收rip报文
	rippacket_Receive();
	return;
}

void routentry_Insert()
{
	printf("routentry_Insert-------------------------------------------------\n");
	struct in_addr tmp_addr,tmp_addr2;
	int j = 0;
	unsigned int tmp;
	//将本地接口表添加到rip路由表里
	for(int i = 0;i<lc_ip_size;i++)
	{
		printf("The size of local interface is enumerating. Now is No.%d\n",i);
		temp_RouteEntry = (TRtEntry *)malloc(sizeof(TRtEntry));
		temp_RouteEntry->pstNext = g_pstRouteEntry->pstNext;
		g_pstRouteEntry->pstNext = temp_RouteEntry;

		inet_pton(AF_INET, pcLocalAddr[i], (void *)&tmp_addr);
		tmp_addr2.s_addr = (pcLocalAddrMask[i] & tmp_addr.s_addr);
		temp_RouteEntry->stIpPrefix = tmp_addr2;
		
		tmp = pcLocalAddrMask[i];
		for(j=0;tmp!=0;j++)
		{
			tmp = tmp << 1;
		}
		temp_RouteEntry->uiPrefixLen = pcLocalAddrMask[i];

		inet_pton(AF_INET, "0.0.0.0", (void *)&temp_RouteEntry->stNexthop);
		temp_RouteEntry->uiMetric = htonl(1);
		temp_RouteEntry->pcIfname = pcLocalName[i];
		temp_RouteEntry->ttl = 0;
	}
	return ;
}

void localinterf_GetInfo()
{
	printf("localinterf_GetInfo-------------------------------------------------\n");
	struct ifaddrs *pstIpAddrStruct = NULL;
	struct ifaddrs *pstIpAddrStCur  = NULL;
	void *pAddrPtr=NULL;
	const char *pcLo = "127.0.0.1";
	
	getifaddrs(&pstIpAddrStruct); //linux系统函数
	pstIpAddrStCur = pstIpAddrStruct;
	
	int i = 0;
	while(pstIpAddrStruct != NULL)
	{
		if(pstIpAddrStruct->ifa_addr->sa_family==AF_INET)
		{
			pAddrPtr = &((struct sockaddr_in *)pstIpAddrStruct->ifa_addr)->sin_addr;
			char cAddrBuf[INET_ADDRSTRLEN];
			memset(&cAddrBuf,0,sizeof(INET_ADDRSTRLEN));
			inet_ntop(AF_INET, pAddrPtr, cAddrBuf, INET_ADDRSTRLEN);
			if(strcmp((const char*)&cAddrBuf,pcLo) != 0)
			{
				pcLocalAddr[i] = (char *)malloc(sizeof(INET_ADDRSTRLEN));
				pcLocalName[i] = (char *)malloc(sizeof(IF_NAMESIZE));
				pcLocalAddrMask[i] = ((struct sockaddr_in *)pstIpAddrStruct->ifa_netmask)->sin_addr.s_addr;
				strcpy(pcLocalAddr[i],(const char*)&cAddrBuf);
				strcpy(pcLocalName[i],(const char*)pstIpAddrStruct->ifa_name);
				i++;
				lc_ip_size ++;
			}	
		}
		pstIpAddrStruct = pstIpAddrStruct->ifa_next;
	}
	freeifaddrs(pstIpAddrStCur);//linux系统函数

	for(int i=0;i<lc_ip_size;i++)
	{
		printf("pcLocalAddr[%d] is %s",i,pcLocalAddr[i]);
	}
	return ;
}

int main(int argc,char* argv[])
{
	printf("Start!!\n");
	g_pstRouteEntry = (TRtEntry *)malloc(sizeof(TRtEntry));
	if(g_pstRouteEntry == NULL)
	{
		perror("g_pstRouteEntry malloc error !\n");
		return -1;
	}
	g_pstRouteEntry->pstNext = NULL;
	printf("successfully molloc space\n");
	localinterf_GetInfo();
	routentry_Insert();
	ripdaemon_Start();
	return 0;
}


