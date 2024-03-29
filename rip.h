#ifndef __MYRIP_H
#define __MYRIP_H
#include <stdio.h>  
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>


#define RIP_VERSION    	2
#define RIP_REQUEST    	1
#define RIP_RESPONSE   	2
#define RIP_INFINITY  	16
#define RIP_PORT		520
#define RIP_PACKET_HEAD	4
#define RIP_MAX_PACKET  504
#define RIP_MAX_ENTRY   25
#define ROUTE_MAX_ENTRY 256
#define RIP_GROUP		"224.0.0.9"

#define RIP_CHECK_OK    1
#define RIP_CHECK_FAIL  0
#define AddRoute        24
#define DelRoute        25

typedef struct RipEntry
{
	unsigned short usFamily;
	unsigned short usTag;
	struct in_addr stAddr;
	struct in_addr stPrefixLen;//mask
	struct in_addr stNexthop;
	unsigned int uiMetric;
}TRipEntry;

struct ip_mreq
{
       struct in_addr imr_multiaddr;   /* IP multicast address of group */
       struct in_addr imr_interface;   /* local IP address of interface */
};

typedef struct  RipPacket
{
	unsigned char ucCommand;
	unsigned char ucVersion;
	unsigned short usZero; 
	TRipEntry RipEntries[RIP_MAX_ENTRY];
}TRipPkt;


typedef struct RouteEntry
{
	struct RouteEntry *pstNext;
	struct in_addr stIpPrefix;
	unsigned int  uiPrefixLen;//mask
	struct in_addr stNexthop;
	unsigned int   uiMetric;
	char  *pcIfname;
	unsigned int ttl;
}TRtEntry;

typedef struct SockRoute
{
	unsigned int uiPrefixLen;
	struct in_addr stIpPrefix;
	unsigned int uiIfindex;
	struct in_addr stNexthop;
	unsigned int uiCmd;
}TSockRoute;

void route_SendForward(unsigned int uiCmd,TRtEntry *pstRtEntry);
void requestpkt_Encapsulate();
void rippacket_Receive();
void rippacket_Send(struct in_addr stSourceIp);
void rippacket_Multicast(char *pcLocalAddr,int pkt_len);
void request_Handle(struct in_addr stSourceIp);
void response_Handle(struct in_addr stSourceIp,int length);
void rippacket_Update();
void routentry_Insert();
void localinterf_GetInfo();
void ripdaemon_Start();
void *thr_fn(void *arg);

#endif

