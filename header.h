#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#define ETHERTYPE_ARP 0x0806
struct ether_header
{
	uint8_t ether_dhost[6];      
	uint8_t ether_shost[6];
	uint16_t ether_type;
};
struct arp{
	uint16_t hdtype;
	uint16_t pttype;
	uint8_t hdadd_len;
	uint8_t ptadd_len;
	uint16_t op;
	uint8_t	ar_sha[6];
	uint8_t ar_spa[4];
	uint8_t	ar_tha[6];
	uint8_t ar_tpa[4];
};
struct p_thread{
	char argv1[10];
	char argv2[20];
	char argv3[20];
};
struct p1_thread{
	pcap_t * handle;
	unsigned char packet[42];
};
void * func(void * p_thread);
