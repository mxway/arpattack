#ifndef COMMON_INCLUDE_H
#define COMMON_INCLUDE_H
#include <string>
#include <WinSock2.h>
using namespace std;

enum PROTOCOL_TYPE{MXL_UNKNOWN_PROTOCOL,MXL_ARP,MXL_RARP,MXL_IP,
					MXL_TCP,MXL_UDP,
					MXL_ICMP};



#define WM_CAPTURE_PACKET WM_USER+110

struct MyNetCard
{
	string	netCardName;//网卡名
	string	description;//网卡描述
	string  ipaddr;//网卡ip地址
	string  netmask;//掩码
	string	friendName;//友好名称
};

struct DataPacket
{
	int					packetNum;//数据包编号
	PROTOCOL_TYPE		packetType;//数据包类型
	int					packetLen;//当前数据包长度
	//u_char				*data;//从网卡读取到的数据
};


#endif