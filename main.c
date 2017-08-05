#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "header.h"
#define ETHERTYPE_ARP 0x0806

int main(int argc, char ** argv){
	int thr_id;
	int status;
	int i=0;
	pthread_t thread[10];
	struct p_thread * p_thread;
	p_thread = (struct p_thread *)malloc(sizeof(struct p_thread));
	printf("%d\n",argc);
	for(i=2;i<=argc-2;i+=2){
		printf("#\n");
		strncpy(p_thread->argv1,argv[1],10);
		strncpy(p_thread->argv2,argv[i],20);
		strncpy(p_thread->argv3,argv[i+1],20);
		printf("# = %s %s %s\n",p_thread->argv1,p_thread->argv2,p_thread->argv3);
		thr_id = pthread_create(&thread[i/2-1],NULL,func,(void *)p_thread);
		sleep(2);
	}
	for(i=0;i<(argc-2)/2;i++){
		pthread_join(thread[i], (void **)&status);
	}
	return 0;
}
