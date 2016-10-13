#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
//#include<protocols/routed.h> 
#include<sys/socket.h>
#include<time.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include "router.h"

struct ripfileHeader
{
	u_int32_t   n_dst;		/* destination net or host */
	u_int32_t   n_mask;		/* netmask in RIPv2 */
	u_int32_t   n_nhop;		/* optional next hop in RIPv2 */
	u_int32_t   n_metric;
	char intfc[128];
	struct ripfileHeader *nextfHead;
};

struct ripfileHeader *fileAnchor = NULL;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
//void print_rip_packet(const u_char * , int );
void PrintData (const u_char * , int);

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
//-------rip headers------


struct netinfo {
	u_int16_t   n_family;
#define	    RIP_AF_INET	    htons(AF_INET)
#define	    RIP_AF_UNSPEC   0
#define	    RIP_AF_AUTH	    0xffff
	u_int16_t   n_tag;		/* optional in RIPv2 */
	u_int32_t   n_dst;		/* destination net or host */
#define	    RIP_DEFAULT	    0
	u_int32_t   n_mask;		/* netmask in RIPv2 */
	u_int32_t   n_nhop;		/* optional next hop in RIPv2 */
	u_int32_t   n_metric;		/* cost of route */
};

struct rip {
	u_int8_t    rip_cmd;		/* request/response */
	u_int8_t    rip_vers;		/* protocol version # */
	u_int16_t   rip_res1;		/* pad to 32-bit boundary */
};
#define	RIPCMD_REQUEST		1	/* want info */
#define	RIPCMD_RESPONSE		2	/* responding to request */
#define	RIPCMD_TRACEON		3	/* turn tracing on */
#define	RIPCMD_TRACEOFF		4	/* turn it off */

int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;

	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");

	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}

	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];

	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);

	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;

	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{

		case 2:  //IGMP Protocol
			++igmp;
			break;

		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;

		case 17: //UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;

		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");

	print_ip_header(Buffer,Size);

	fprintf(logfile , "\n");
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile , "\n");
	fprintf(logfile , "                        DATA Dump                         ");
	fprintf(logfile , "\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);

	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);

	fprintf(logfile , "Data Payload\n");
	PrintData(Buffer + header_size , Size - header_size );

	fprintf(logfile , "\n###########################################################");
}

void print_udp_packet(const u_char *Buffer , int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

	print_ip_header(Buffer,Size);

	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);

	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);

	fprintf(logfile , "Data Payload\n");

	if(ntohs(udph->source) == 520 )
	{
		//memset(&source, 0, sizeof(source));
		//source.sin_addr.s_addr = iph->saddr;
		//struct myrt_table* ripBentry= (struct myrt_table*)lookup_route(source.sin_addr );

		//if (strcmp(ripBentry->intfc,"eth2") == 0)  // have to check for functional change
		process_rip_packet(Buffer , Size);
		//else if (strcmp(ripBentry->intfc,"eth1") == 0)	// have to check for functional change
		process_rip_packet2(Buffer , Size);

		//	parse_rip_Fileheader(Buffer , Size);

	}
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);

	fprintf(logfile , "\n###########################################################");
}

void process_rip_packet(const char *Buffer , int Size)
{
	struct rip *ripE = (struct rip*) malloc(sizeof(struct rip));
	struct netinfo *ripH = (struct netinfo*) malloc(sizeof(struct netinfo));

	//int ripHLEN =12 ;
	ripE->rip_cmd = 2;
	ripE->rip_vers = 2;

	struct sockaddr_in dest1,dest2,netmask,nexthop;
	int flag =0;
	inet_aton("10.1.0.0", &dest1.sin_addr);
	inet_aton("10.10.2.0", &dest2.sin_addr);
	inet_aton("255.255.255.0", &netmask.sin_addr);
	inet_aton("0.0.0.0", &nexthop.sin_addr);

	int sockfd, portno =520, n;
	struct in_addr localInterface;
	struct sockaddr_in groupSock,sendSock;
	struct hostent *server;
	socklen_t fromlen;
	char buffer[1024];

	memset((char *) &sendSock, 0, sizeof(sendSock));
	sendSock.sin_family = AF_INET;
	sendSock.sin_addr.s_addr= htonl(INADDR_ANY);
	sendSock.sin_port=htons(520); //source port for outgoing packets

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	memset((char *) &groupSock, 0, sizeof(groupSock));
	groupSock.sin_family = AF_INET;
	groupSock.sin_addr.s_addr = inet_addr("224.0.0.9");
	groupSock.sin_port = htons(520);

	bind(sockfd,(struct sockaddr *)&sendSock,sizeof(sendSock));
	localInterface.s_addr = inet_addr("10.10.1.1");
	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0)
	{
		perror("Setting local interface error");
		exit(1);
	}
	else
		printf("Setting the local interface...OK\n");


	ripH->n_family = htons(AF_INET);
	ripH->n_tag = 0;
	ripH->n_dst = (u_int32_t)dest1.sin_addr.s_addr;


	ripH->n_mask = (u_int32_t)netmask.sin_addr.s_addr;
	ripH->n_nhop = (u_int32_t)nexthop.sin_addr.s_addr;
	ripH->n_metric = htonl(1);

	bzero(buffer,1024);
	memcpy(buffer,ripE,  sizeof(struct rip));
	memcpy(buffer+sizeof(struct rip),ripH , sizeof(struct netinfo));
	ripH->n_dst = (u_int32_t)dest2.sin_addr.s_addr;
	memcpy(buffer+sizeof(struct rip)+sizeof(struct netinfo),ripH , sizeof(struct netinfo));
	//int BUFLEN=sizeof(struct rip)+2*sizeof(struct netinfo);
	//buffer[BUFLEN] = '\0';
	n = sendto(sockfd,buffer,44, 0,(struct sockaddr *) &groupSock,sizeof(groupSock));
	printf("Size of rip packet sent %d\n",n);
	sleep(5);
	close(sockfd);

}

void process_rip_packet2(const char *Buffer , int Size)
{

	unsigned short iphdrlen;

	struct rip *ripE =(struct rip*)malloc(sizeof(struct rip));
	struct netinfo *ripH = (struct netinfo *)malloc(sizeof(struct netinfo));

	ripE->rip_cmd = 2;
	ripE->rip_vers = 2;

	struct sockaddr_in dest1,dest2,netmask,nexthop;

	inet_aton("10.1.0.0", &dest1.sin_addr);
	inet_aton("10.10.1.0", &dest2.sin_addr);
	inet_aton("255.255.255.0", &netmask.sin_addr);
	inet_aton("0.0.0.0", &nexthop.sin_addr);

	int sockfd, portno =520, n;
	struct in_addr localInterface;
	struct sockaddr_in groupSock,sendSock;
	struct hostent *server;
	socklen_t fromlen;
	char buffer[1024];

	memset((char *) &sendSock, 0, sizeof(sendSock));
	sendSock.sin_family = AF_INET;
	sendSock.sin_addr.s_addr= htonl(INADDR_ANY);
	sendSock.sin_port=htons(520); //source port for outgoing packets

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	memset((char *) &groupSock, 0, sizeof(groupSock));
	groupSock.sin_family = AF_INET;
	groupSock.sin_addr.s_addr = inet_addr("224.0.0.9");
	groupSock.sin_port = htons(520);

	bind(sockfd,(struct sockaddr *)&sendSock,sizeof(sendSock));
	localInterface.s_addr = inet_addr("10.10.2.2");
	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0)
	{
		perror("Setting local interface error");
		exit(1);
	}
	else
		printf("Setting the local interface...OK\n");


	ripH->n_family = htons(AF_INET);
	ripH->n_tag = 0;
	ripH->n_dst = (u_int32_t)dest1.sin_addr.s_addr;


	ripH->n_mask = (u_int32_t)netmask.sin_addr.s_addr;
	ripH->n_nhop = (u_int32_t)nexthop.sin_addr.s_addr;
	ripH->n_metric = htonl(1);

	bzero(buffer,1024);
	memcpy(buffer ,ripE,  sizeof(struct rip));
	memcpy(buffer+sizeof(struct rip),ripH , sizeof(struct netinfo));
	ripH->n_dst = (u_int32_t)dest2.sin_addr.s_addr;
	memcpy(buffer+sizeof(struct rip)+sizeof(struct netinfo),ripH,sizeof(struct netinfo));
	//fromlen=sizeof( struct sockaddr_in);

	n = sendto(sockfd,buffer,44, 0,(struct sockaddr *) &groupSock,sizeof(groupSock));
	sleep(5);
	close(sockfd);

}
/*
void add_rip_Fileheader(const char *Buffer , int Size)
{
	unsigned short iphdrlen;
	struct ripfileHeader *fileH = NULL;
	struct ripfileHeader *temp = fileAnchor; 
    temp = fileH;
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4; 
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	struct rip *ripE = (struct rip*) (Buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	struct netinfo *ripH = (struct netinfo*) (Buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr) + 4);
	
	int ripHLEN =12 ;
//memset(&source, 0, sizeof(source));
 //   source.sin_addr.s_addr = iph->saddr;
	
//	struct myrt_table* ripBentry= (struct myrt_table*)lookup_route(source.sin_addr ); // or iph->ip_src to check or struct in_addr
	
	while(ripHLEN!=ntohs(udph->len))
	{
		fileH =(struct ripfileHeader*) malloc(sizeof (struct ripfileHeader)); 
		
		/* passing the rip values in file structure*/

//		   fileH->n_dst= ripH->n_dst ;		/* destination net or host */
//		   fileH->n_mask= ripH->n_mask;		/* netmask in RIPv2 */
//		   fileH->n_nhop= ripH->n_nhop;		/* optional next hop in RIPv2 */
//		   fileH->n_metric = ripH->n_metric;
//		   strcpy(fileH->intfc,ripBentry->intfc);
//		   temp = fileH;
//   fileH=fileH->nextfHead;
//		   fileH->nextfHead=NULL;

//		ripHLEN+=20;
//		ripH+=1;

//	}
//}	

void del_rip_Fileheader(struct ripfileHeader *entry)
{
	struct ripfileHeader *f_walker =fileAnchor;
	struct ripfileHeader *temp = NULL;

	while(f_walker->nextfHead!=0)
	{
		temp = (struct ripfileHeader*) malloc(sizeof (struct ripfileHeader));

		if(strcmp(f_walker->intfc , "eth2") == 0)
		{
			temp = f_walker;
			temp->nextfHead = NULL;
			f_walker= f_walker->nextfHead ;

		}
		else if(strcmp(f_walker->intfc , "eth1") == 0)
		{
			temp = f_walker;
			temp->nextfHead = NULL;
			f_walker= f_walker->nextfHead ;

		}

		free(temp);
	}

	return ;
}

struct ripfileHeader* parse_rip_Fileheader(const char *Buffer , int Size)
{
	int idx = 1;
	struct sockaddr_in dest1,dest2,dest3,netmask,nexthop;
	struct ripfileHeader *temp =fileAnchor;
	struct ripfileHeader *fileH = NULL;
	inet_aton("10.10.2.0", &dest1.sin_addr);
	inet_aton("10.10.1.0", &dest2.sin_addr);
	inet_aton("10.1.0.0", &dest3.sin_addr);
	inet_aton("255.255.255.0", &netmask.sin_addr);
	inet_aton("0.0.0.0", &nexthop.sin_addr);

	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	struct rip *ripE = (struct rip*) (Buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	struct netinfo *ripH = (struct netinfo*) (Buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr) + 4);


	while(temp->nextfHead!=NULL)
	{
		if(temp = NULL)
		{
			if(idx = 1)
			{
				fileH =(struct ripfileHeader*) malloc(sizeof (struct ripfileHeader));
				fileH->n_dst= (u_int32_t)dest1.sin_addr.s_addr;			/* destination net or host */
				fileH->n_mask= (u_int32_t)netmask.sin_addr.s_addr;		/* netmask in RIPv2 */
				fileH->n_nhop= (u_int32_t)nexthop.sin_addr.s_addr;		/* optional next hop in RIPv2 */
				fileH->n_metric =  htonl(1);
				strcpy(fileH->intfc,"eth1");
				temp = fileH;
				fileH=fileH->nextfHead;
				fileH->nextfHead=NULL;
				idx++;
			}
			if(idx = 2)
			{
				fileH =(struct ripfileHeader*) malloc(sizeof (struct ripfileHeader));
				fileH->n_dst= (u_int32_t)dest2.sin_addr.s_addr;		/* destination net or host */
				fileH->n_mask= (u_int32_t)netmask.sin_addr.s_addr;		/* netmask in RIPv2 */
				fileH->n_nhop= (u_int32_t)nexthop.sin_addr.s_addr;		/* optional next hop in RIPv2 */
				fileH->n_metric =  htonl(1);
				strcpy(fileH->intfc,"eth2");
				temp = fileH;
				fileH=fileH->nextfHead;
				fileH->nextfHead=NULL;
				idx++;
			}
			if(idx = 3)
			{
				fileH =(struct ripfileHeader*) malloc(sizeof (struct ripfileHeader));
				fileH->n_dst= (u_int32_t)dest3.sin_addr.s_addr;		/* destination net or host */
				fileH->n_mask= (u_int32_t)netmask.sin_addr.s_addr;		/* netmask in RIPv2 */
				fileH->n_nhop= (u_int32_t)nexthop.sin_addr.s_addr;		/* optional next hop in RIPv2 */
				fileH->n_metric =  htonl(1);
				strcpy(fileH->intfc,"eth3");
				temp = fileH;
				fileH=fileH->nextfHead;
				fileH->nextfHead=NULL;
				idx++;
			}

		}
		/*while(temp->nextfHead != NULL)
        {
            if( fileH->n_dst != ripH->n_dst)
            add_rip_Fileheader(Buffer , Size);
        }	*/
	}
	return fileH;
}

void PrintData (const u_char * data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet

				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		}

		if(i%16==0) fprintf(logfile , "   ");
		fprintf(logfile , " %02X",(unsigned int)data[i]);

		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++)
			{
				fprintf(logfile , "   "); //extra spaces
			}

			fprintf(logfile , "         ");

			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
				{
					fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else
				{
					fprintf(logfile , ".");
				}
			}

			fprintf(logfile ,  "\n" );
		}
	}
}
