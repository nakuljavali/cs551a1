#include <stdio.h>
#include <pcap.h>
#include <pthread.h>

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

void *capture()
{
        int count=0;
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


void *printer()
{	
	while(1)
	{
		usleep(read_time);	

		if(read_verbose == 0)
		{
			printf("%d:%d %d %d\n",(int)header->ts.tv_sec,(int)header->ts.tv_usec,packet_count,byte_count); 

			packet_count = 0;
			byte_count = 0;

		}else
		{
		        printf("%d:%d %d %ld %d %d %d\n",(int)header->ts.tv_sec,(int)header->ts.tv_usec,packet_count,
										byte_count,count_tcp,count_udp,count_icmp);
  
                        packet_count = 0;
                        byte_count = 0;
			count_tcp = 0;
			count_udp = 0;
			count_icmp = 0;
       	        }
	}

}
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
   		
		}




	}

}




int main (int argc, char *argv[])
{

	
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	u_int size_ip;
	int time_check,time_check2;


//////////////////////// filter variables //////////////////////////////
	char filter_exp[2] = "ip";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int test=0;
//////////////////////// filter variabels end //////////////////////////

////////////////////////////// all the counts .../////////////////////
	int packet_count = 0;
	long int byte_count = 0;
	int count_tcp = 0;
	int count_udp = 0;
	int count_icmp = 0;
//////////////////////////// all the counts .. ///////////////////////


///////////////////////// parser variables /////////////////////////////////////
	int i=1;
        char read_pcap;
        char read_interface;
        int read_time=1;
        int read_verbose=0;
        char read_write;        
	int read_online=0;
///////////////////////// parser variable ends ///////////////////////////////


        while(i<argc)
        {
                if(strcmp(argv[i],"-r")==0)
                { read_pcap = argv[i+1];}       
                
                else if(strcmp(argv[i],"-i")==0)
                { read_pcap = argv[i+1];
		  read_online = 1;}       

                else if(strcmp(argv[i],"-T")==0)
                { read_time = atoi(argv[i+1]);} 
                
                else if(strcmp(argv[i],"-v")==0)
                { read_verbose = 1;}    

                else if(strcmp(argv[i],"-w")==0)
                { if( strcmp(argv[i+1],"-r")==0 && strcmp(argv[i+1],"-i")==0 && strcmp(argv[i+1],"-T")==0 && strcmp(argv[i+1],"-v")==0)
                        read_write = is_stdout;
                  else
                        read_write = argv[i+1]; 
                }

        }


///////////////////////// parser ends //////////////////////////////////





	pcap_lookupnet(argv[1],&net,&mask,errbuf);

	pcap = pcap_open_offline(argv[1],errbuf);

	if(pcap == NULL)
	{
		printf("err: %s",errbuf);
		return 0;
	}

/*
	if(pthread_create(&th_pcap,NULL,capture,0))
	{
		fprintf(stderr,"Creating Capture thread");
		exit(1);
	}

	
	if(pthread_create(&th_print,NULL,printer,0))
	{
		fprintf(stderr,"Creating printing thread");
		exit(1);
	}


	pthread_join(th_pcap,0);
	pthread_join(th_print,0);				*/

////////////////////////////// Threadings End ////////////////////////////////////////////


//////////// check back on this, using filter and compile with offline ///////////////////
	if(read_online==0)
	{	
	        pcap_lookupnet(argv[1],&net,&mask,errbuf);

	        pcap = pcap_open_offline(argv[1],errbuf);
	
	      	if(pcap == NULL)
        	{
       	        	 printf("err: %s",errbuf);
        	        return 0;
        	}	

		        if(pcap_compile(pcap,&fp,"ip",0,0)==-1)
	        {
       		         printf("cannot compile :/");
	        }

        	if(pcap_setfilter(pcap,&fp)==-1)
	        {
        	        printf("cannot install filter");
       		}	

		pcap_next_ex(pcap,&header,&packet);
		time_check = (int)header->ts.tv_sec;	
		time_check2 = (int)header->ts.tv_usec;
		byte_count = header->len;
		packet_count++;
	
		while(pcap_next_ex(pcap,&header,&packet)>0){
	
			byte_count += header->len;
			packet_count++;
			{
				printf("Time Frame: %d:%d ",(int)header->ts.tv_sec,(int)header->ts.tv_usec); 	
				printf("Packet Count: %d ",packet_count);
				printf("Byte Count: %ld\n",byte_count); 
				time_check = (int)header->ts.tv_sec; 

				if(packet_count == 2443)
				break;
			}

		}	
	}
	else
	{
	        int count=0;
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

		if(pcap_compile(handle,&fp,"ip",0,0)==-1)
        		{
		                printf("cannot compile :/");
		        }

	        if(pcap_setfilter(handle,&fp)==-1)
		        {
                		printf("cannot install filter");
		        }		

	        pcap_loop(handle,-1,processor,(u_char*) &count);

	        return 0;
	}


}
