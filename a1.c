#include <stdio.h>
#include <pcap.h>
#include <pcap/pcap.h>

void processor(u_char *arg,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	int i=0, *counter = (int *)arg;

	printf("Packet Count: %d\n", ++(*counter));
	printf("Received Packet Size: %d\n",pkthdr->len);
	printf("Payload:\n");

	for(i=0; i <pkthdr->len;i++){

	if(isprint(packet[i]))
	printf("%c", packet[i]);
	else
	printf(".");

	if((i%16==0 && i!=0)||i==pkthdr->len-1)
	printf("\n");


	}

}

int main(int argc, char *argv[])
{	int count=0;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;	

	dev = pcap_lookupdev(errbuf);
	
	if(dev == NULL){
	printf("No device found \n"); 
	printf("Error: %s\n",errbuf);
	return 0;
 	}

	printf("Device found at: %s \n",dev);


	handle = pcap_open_live(dev,2048,1,512,errbuf);

	printf("here");
	pcap_loop(handle,-1,processor,(u_char*) &count);

	return 0;
}



