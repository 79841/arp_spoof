arp_spoof: main.o arp_func.o
	gcc -o arp_spoof main.o arp_func.o -lpcap -lpthread
main.o: main.c header.h
	gcc -c -o main.o main.c -lpcap -lpthread
arp_func.o: arp_func.c header.h
	gcc -c -o arp_func.o arp_func.c -lpcap -lpthread
