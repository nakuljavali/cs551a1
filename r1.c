#include <stdio.h>
#include <pcap.h>
#include <pthread.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


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

	const struct sniff_ethernet *ethernet; 
	const struct sniff_ip *ip;             
	const struct sniff_tcp *tcp;           
	const char *payload;                   

	int size_ip;
	int size_tcp;
	int size_payload;
	
	ethernet = (struct sniff_ethernet*)(packet);
	
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	switch(ip->ip_p) {
		case IPPROTO_TCP:
			count_tcp++;
			break;
		case IPPROTO_UDP:
			count_ucp++;
			return;
		case IPPROTO_ICMP:
			count_icmp++;
			return;
		default:
			count_other++;
			return;
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
	int count_other = 0;
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
