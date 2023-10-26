#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
 
#include <stdio.h>
#include <stdlib.h>
 
 
#pragma   comment   (lib,"Ws2_32.lib")
#include "ntp_client.h"
 
#define JAN_1970 0x83aa7e80
#pragma warning(disable:4996)
 
char* ntp_host[] = {
    "203.107.6.88",
	"182.92.12.11",
	"64.62.194.188",
	"17.253.84.123",
	"17.253.84.125",
	"17.253.114.253",
	"17.253.116.253",
	"20.189.79.72",
	"52.148.114.188",
	"40.119.6.228",
	"51.137.137.111",
	"223.255.185.2",
	"223.255.185.3",
	"202.118.1.130",
	"202.118.1.81",
	"116.13.10.10",
	"114.118.7.161"
};
typedef struct _timeval
{
	long    tv_sec;         /* seconds */
	long    tv_usec;        /* and microseconds */
}timeval;

void Get_time_t(time_t* t)
{
	*t = 0;
	WSADATA wsaData = {0};
	// Initialize Winsock
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) return;
	int result, count;
	int sockfd = 0, rc;
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) {
		WSACleanup();
		return;
	}
	fd_set pending_data = {0};
	timeval block_time = {0};
	NTPPacket ntpSend = { 0 };
	ntpSend.nControlWord = 0x1B;
	NTPPacket ntpRecv;
	SOCKADDR_IN addr_server;
	addr_server.sin_family = AF_INET;
	addr_server.sin_port = htons(123);//NTP服务默认为123端口号

	srand(time(NULL));
 
 
	int idx = rand() % 16;
 

 


	addr_server.sin_addr.S_un.S_addr = inet_addr(ntp_host[idx]); //该地址为阿里云NTP服务器的公网地址，其他NTP服务器地址可自行百度搜索。
	SOCKADDR_IN sock;
	int len = sizeof(sock);

	if ((result = sendto(sockfd, (const char*)&ntpSend, sizeof(NTPPacket), 0, (SOCKADDR*)&addr_server, sizeof(SOCKADDR))) < 0)
	{
		int err = WSAGetLastError();
		closesocket(sockfd);
		WSACleanup();
		return;
	}
	FD_ZERO(&pending_data);
	FD_SET(sockfd, &pending_data);
	//timeout 10 sec
	block_time.tv_sec = 5;
	block_time.tv_usec = 0;
	if (select(sockfd + 1, &pending_data, NULL, NULL, &block_time) > 0)
	{
		//获取的时间为1900年1月1日到现在的秒数
		if ((count = recvfrom(sockfd, (char*)&ntpRecv, sizeof(NTPPacket), 0, (SOCKADDR*)&sock, &len)) > 0)
			*t = ntohl(ntpRecv.nTransmitTimestampSeconds) - JAN_1970;
	}
	closesocket(sockfd);
	WSACleanup();

}

LONGLONG get_time()
{
	time_t  t;
	Get_time_t(&t);
	while (TRUE)
	{
		if (!t && t <= (time(NULL) - 5000))
		{
			Get_time_t(&t);
			continue;
		}
		break;
	}
 
	return t;
}
