
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>     /* for signal */
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
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

void process_rip_packet(int);


# define T 30

int flag = T;


int  main(void)
{
	signal(SIGALRM, process_rip_packet);
	alarm(1);
	while (1);
}

void process_rip_packet(int sig)
{
	if(--flag){
		printf("Wait....%d\n",flag);
	} else{

		unsigned short iphdrlen;

		struct rip *ripE =(struct rip*)malloc(sizeof(struct rip));
		struct netinfo *ripH = (struct netinfo *)malloc(sizeof(struct netinfo));

		ripE->rip_cmd = 2;
		ripE->rip_vers = 2;

		struct sockaddr_in dest1,dest2,netmask,nexthop;

		inet_aton("10.10.3.0", &dest1.sin_addr); //Eth2 RX1
		inet_aton("10.10.2.0", &dest2.sin_addr);//eth3 R1
		inet_aton("255.255.255.0", &netmask.sin_addr);
		inet_aton("0.0.0.0", &nexthop.sin_addr);

		int sockfd, portno =520, n;
		struct in_addr localInterface;
		struct sockaddr_in groupSock,sendSock;
		struct hostent *server;
		socklen_t fromlen;
		char buffer[1024];



		/*server = gethostbyname("rtr3");
        if (server == NULL) {
            fprintf(stderr,"ERROR, no such host\n");
            exit(0);
        }*/

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
		localInterface.s_addr = inet_addr("10.10.3.2");//Eth0 R
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
		ripH->n_metric = htonl(2);
		memcpy(buffer+sizeof(struct rip)+sizeof(struct netinfo),ripH,sizeof(struct netinfo));
		//fromlen=sizeof( struct sockaddr_in);

		n = sendto(sockfd,buffer,sizeof(struct rip)+(2)*sizeof(struct netinfo), 0,(struct sockaddr *) &groupSock,sizeof(groupSock));

		close(sockfd);
		printf("packet sent\n");
		flag=T;
		printf("value of flag: %d\n",flag);
	}

	alarm(1);
}


