#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include "header.h"
#define ETHERTYPE_ARP 0x0806



int main(int argc, char ** argv){
	int thr_id;
	int status;
	int i=0;
	pthread_t thread[10];
	char errbuf[PCAP_ERRBUF_SIZE];
	char p_thread[1000];
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
        if (handle == NULL) {
        	fprintf(stderr, "Couldn't open device %s: %s\n",argv[1], errbuf);
        	exit(0);
        }
	
	//struct p_thread * p_thread;
	//p_thread = (char *)malloc(1000);
	
	printf("%d\n",argc);
	for(i=2;i<=argc-2;i+=2){
		printf("#\n");
		strncpy(p_thread+(i-2)/2*50,argv[1],10);
		strncpy(p_thread+(i-2)/2*50+10,argv[i],20);
		strncpy(p_thread+(i-2)/2*50+30,argv[i+1],20);
		printf("# = %s %s %s\n",p_thread+(i-2)/2*50,p_thread+(i-2)/2*50+10,p_thread+(i-2)/2*50+30);
		thr_id = pthread_create(&thread[i/2-1],NULL,func,(void *)(p_thread+(i-2)/2*50));
		sleep(2);
	}
	//for(i=0;i<(argc-2)/2;i++){
		//pthread_join(thread[i], (void **)&status);
		//pthread_detach(thread[i]);
	//}
	pthread_join(thread[0], (void **)&status);
	pthread_join(thread[1], (void **)&status);
	return 0;
}
