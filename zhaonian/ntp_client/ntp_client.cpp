#include <winsock2.h>
#include <ws2tcpip.h>
#include<ctime>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#pragma   comment   (lib,"Ws2_32.lib")
#include "ntp_client.h"
#include "../lib/xor.h"
using namespace std;
#define JAN_1970 0x83aa7e80
#pragma warning(disable:4996)
  char* ntp_host[] =
{
	skCrypt("203.107.6.88") ,
	skCrypt("182.92.12.11") ,
	skCrypt("64.62.194.188") , 
	skCrypt("17.253.84.123") ,
	skCrypt("17.253.84.125") , 
	skCrypt("17.253.114.253") ,
	skCrypt("17.253.116.253") ,
	skCrypt("20.189.79.72") ,
	skCrypt("52.148.114.188") ,
	skCrypt("40.119.6.228") ,
	skCrypt("51.137.137.111") ,
	skCrypt("223.255.185.2") ,
	skCrypt("223.255.185.3") ,
	skCrypt("202.118.1.130") ,
	skCrypt("202.118.1.81") ,
	skCrypt("116.13.10.10") ,
	skCrypt("114.118.7.161") ,
	skCrypt("114.118.7.161") ,
};
int ntp_client::Get_time_t(time_t& ttime)
{
	ttime = 0;
	WSADATA wsaData;
	// Initialize Winsock
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) return 0;
	int result, count;
	int sockfd = 0, rc;
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0) return 0;
	fd_set pending_data;
	timeval block_time;
	NTPPacket ntpSend = { 0 };
	ntpSend.nControlWord = 0x1B;
	NTPPacket ntpRecv;
	SOCKADDR_IN addr_server;
	addr_server.sin_family = AF_INET;
	addr_server.sin_port = htons(123);//NTP服务默认为123端口号

 
   // 创建随机数生成器
	std::random_device rd;
	std::mt19937 gen(rd());

	// 创建均匀分布对象，指定随机数范围
	std::uniform_int_distribution<> dis(0, 17);

	// 生成随机数
	int idx = dis(gen);
 
	printf("idx %d  %s  \t", idx,ntp_host[idx]);
	addr_server.sin_addr.S_un.S_addr = inet_addr(ntp_host[idx]); //该地址为阿里云NTP服务器的公网地址，其他NTP服务器地址可自行百度搜索。
	SOCKADDR_IN sock;
	int len = sizeof(sock);

	if ((result = sendto(sockfd, (const char*)&ntpSend, sizeof(NTPPacket), 0, (SOCKADDR*)&addr_server, sizeof(SOCKADDR))) < 0)
	{
		int err = WSAGetLastError();
		return 0;
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
			ttime = ntohl(ntpRecv.nTransmitTimestampSeconds) - JAN_1970;
	}
	closesocket(sockfd);
	WSACleanup();
	return 1;
}

LONGLONG ntp_client::get_time()
{
	time_t  t;
	ntp_client::Get_time_t(t);
	while (true)
	{
		if (!t && t <= (time(NULL) - 5000))
		{
			ntp_client::Get_time_t(t);
			continue;
		} 
		if (t>0)
		{
			break;
		}
	}
	return t;
}
