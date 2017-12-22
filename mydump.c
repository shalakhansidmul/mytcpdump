/**
 * CSE 508 Network Security
 * Home Work 2
 * Submitted by: Shalaka Sidmul
 * SBU ID: 111367731
 * Date: 13-Oct-2017
 */
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ether.h>
#include <getopt.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define SIZE_ICMP 8
#define SIZE_ARP 14
#define SIZE_UDP 8
char * matchString = NULL;
/* IP header */
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

/* TCP header */
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

struct udpheader {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

struct arpheader {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

char *
getTimeStampOfPacket(const struct pcap_pkthdr* header);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
	return;
}
/* get time stamp of packet in human readable format */
char * getTimeStampOfPacket(const struct pcap_pkthdr* header){
	struct tm *timeInfo;
	char buffer[80];
	char ts[64];
	timeInfo = localtime(&(header->ts.tv_sec));
	strftime(buffer,80, "%Y-%m-%d %X",timeInfo);
	snprintf(ts, sizeof ts, "%s.%06ld", buffer,(long int)header->ts.tv_usec);
	char *timeStamp = (char *)malloc(sizeof(ts));
	strcpy(timeStamp, ts);
	return(timeStamp);
}

int checkIfMatchStringPresentInPayload(const u_char *payload, int len,char * protocol){
	int status = 0;
	/* special handling for UDP is required as the UDP payload
	 * can contain non-printable EOF characters which strstr()
	 * woud consider as enf of source (haystack) string for comparison */
	if(strcmp(protocol,"UDP") == 0){
		char * buffer = (char *)calloc(len,sizeof(char));
		int i;
		const u_char *ch;
		ch = payload;
		for(i = 0; i < len; i++) {
				if (isprint(*ch))
					buffer[i] = *ch;
				else
					buffer[i] = '.';
				ch++;
		}
		if(strstr(buffer,matchString) != NULL)
				status = 1;
		free(buffer);
	}else{
		if(strstr((char *)payload, matchString) != NULL)
			status = 1;
	}
	return status;
 }

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	struct ether_header *etheader;
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcpHeader;      /* The TCP header */
	const struct udpheader * udpHeader;		/* The UDP header */
	const char *payload;            		/* Packet payload */
	char *timeStamp;						/* Time stamp YYYY-MM-DD HH:MM:SS.Microseconds*/
	char sourceMACAddr[30];					/* Source MAC address */
	char destinationMACAddr[30];			/* Destination MAC address */
	char etherType[20];						/* Type of ethernet protocol IP, ARP, etc*/
	char lengthOfPacket[50];				/* Length of entire packet */
	char sourceIPAddr[40]; 					/* Source IP Address */
	char destIPAddr[40]; 					/* Destination IP Address */
	int sourcePort;							/* Port number at source */
	int destPort;							/* Port number at destination */
	char protocol[6];						/* Protocol */
	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;						/* size of packet payload */
	int option;								/* for command line option */

	/* get time stamp of packet in human readable format */
	timeStamp = getTimeStampOfPacket(header);
	/* Desination and Source MAC address*/
	etheader = (struct ether_header *)packet;
	snprintf(destinationMACAddr,sizeof destinationMACAddr, "%s",ether_ntoa((struct ether_addr *)etheader->ether_dhost));
	snprintf(sourceMACAddr,sizeof sourceMACAddr, "%s",ether_ntoa((struct ether_addr *)etheader->ether_shost));
	/* Ether Type */
	snprintf(etherType,sizeof etherType ," type 0x%.4x", ntohs(etheader->ether_type));
	/* length of packet */
	snprintf(lengthOfPacket, sizeof lengthOfPacket, "length( %d )" ,header->len);
	if(ntohs(etheader->ether_type) == ETHERTYPE_IP){
		/* define/compute ip header offset*/
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		/* determine protocol */
		switch(ip->ip_p) {
		case IPPROTO_TCP:
			strcpy(protocol,"TCP");
			break;
		case IPPROTO_UDP:
			strcpy(protocol,"UDP");
			break;
		case IPPROTO_ICMP:
			strcpy(protocol,"ICMP");
			break;
		case IPPROTO_IP:
			strcpy(protocol,"IP");
			break;
		default:
			strcpy(protocol,"OTHER");
			break;
		}
		if(strcmp(protocol,"TCP") == 0){
			/* define/compute tcp header offset */
			tcpHeader = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			int size_tcp = TH_OFF(tcpHeader)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			sourcePort = ntohs(tcpHeader->th_sport);
			destPort = ntohs(tcpHeader->th_dport);

			/* source and destination IP addresses*/
			snprintf(sourceIPAddr,sizeof sourceIPAddr, "%s:%d", inet_ntoa(ip->ip_src),sourcePort);
			snprintf(destIPAddr,sizeof destIPAddr, "%s:%d", inet_ntoa(ip->ip_dst), destPort);
			//printf("\n %s -> %s ",sourceIPAddr,destIPAddr);

			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			/*
			 * Print payload data; it might be binary, so don't just
			 * treat it as a string.
			 */
		}else if(strcmp(protocol,"UDP") == 0){
			udpHeader = (struct udpheader *)(packet  + SIZE_ETHERNET + size_ip);
			sourcePort = ntohs(udpHeader->uh_sport);
			destPort = ntohs(udpHeader->uh_dport);
			snprintf(sourceIPAddr,sizeof sourceIPAddr, "%s:%d", inet_ntoa(ip->ip_src),sourcePort);
			snprintf(destIPAddr,sizeof destIPAddr, "%s:%d", inet_ntoa(ip->ip_dst), destPort);
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
			size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
		}else if(strcmp(protocol,"ICMP") == 0){
			struct icmphdr *icmph = (struct icmphdr *)(packet + SIZE_ETHERNET + size_ip);
			snprintf(sourceIPAddr,sizeof sourceIPAddr, "%s", inet_ntoa(ip->ip_src));
			snprintf(destIPAddr,sizeof destIPAddr, "%s", inet_ntoa(ip->ip_dst));
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_ICMP);
			size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_ICMP);
		}else if(strcmp(protocol,"OTHER") == 0){
			printf("\n%s %s -> %s %s %s \n", timeStamp,sourceMACAddr,destinationMACAddr, etherType, lengthOfPacket);
			return;
		}
		if(matchString !=NULL){
			if(size_payload > 0){
				int printPayload = checkIfMatchStringPresentInPayload(payload,size_payload, protocol);
				if( printPayload == 1){
					printf("\n%s %s -> %s %s %s \n", timeStamp,sourceMACAddr,destinationMACAddr, etherType, lengthOfPacket);
					printf("%s -> %s %s \n",sourceIPAddr, destIPAddr, protocol);
					print_payload(payload, size_payload);
				}
			}
		}else{
			printf("\n%s %s -> %s %s %s \n", timeStamp,sourceMACAddr,destinationMACAddr, etherType, lengthOfPacket);
			printf("%s -> %s %s \n",sourceIPAddr, destIPAddr, protocol);
			print_payload(payload, size_payload);
		}
	}else if(ntohs(etheader->ether_type) == ETHERTYPE_ARP){
		struct arpheader * arpHeader = (struct arpheader *)(packet + SIZE_ETHERNET + size_ip);
		int size_arp =  header->len - SIZE_ETHERNET;
		size_payload = size_arp - SIZE_ARP;
		payload = (u_char *)(packet + SIZE_ETHERNET + size_arp);
		if(matchString !=NULL){
			if(size_payload > 0 && (strstr((char *)payload, matchString))!=NULL){
				printf("\n%s %s -> %s %s %s \n  ", timeStamp,sourceMACAddr,destinationMACAddr, etherType, lengthOfPacket);
				printf("Hardware type: %s\n", (ntohs(arpHeader->htype) == 1) ? "Ethernet" : "Unknown");
				printf("Protocol type: %s\n", (ntohs(arpHeader->ptype) == 0x0800) ? "IPv4" : "Unknown");
				printf("Operation: %s\n", (ntohs(arpHeader->oper) == 1)? "ARP Request" : "ARP Reply");
				print_payload(payload, size_payload);
			}
		}else{
			printf("\n%s %s -> %s %s %s \n", timeStamp,sourceMACAddr,destinationMACAddr, etherType, lengthOfPacket);
			printf("%s ", (ntohs(arpHeader->htype) == 1) ? "Ethernet" : "Unknown");
			printf("%s ", (ntohs(arpHeader->ptype) == 0x0800) ? "IPv4" : "Unknown");
			printf("%s ", (ntohs(arpHeader->oper) == 1)? "ARP Request" : "ARP Reply");
			if(ntohs(arpHeader->htype) == 1){
				printf(" who has ");
				int i;
			    for(i=0; i<4;i++)
			        printf("%d.", arpHeader->sha[i]);
			    printf(" tell ");
			    for(i=0; i<4;i++)
			        printf("%d.", arpHeader->sha[i]);
			    printf("\n");
			}
			print_payload(payload, size_payload);
		}

	}
	free(timeStamp);
	return;
}
int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	extern char *optarg;
	extern int optind;
	struct bpf_program bpfProg;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int option;
	int i;
	char *dev = NULL;			/* capture device name */
	char* pcapFile = NULL;
	char * bpf_filter_expr = NULL;
	int sniffInterface = 0;
	int sniffFromFile = 0;
	int lastOptIndex = 0;
	while((option = getopt(argc,argv,"irs")) != -1){
		switch(option){
		case 'i':
			dev  = argv[optind];
			sniffInterface = 1;
			break;
		case 'r':
			pcapFile = argv[optind];
			sniffFromFile =1;
			break;
		case 's':
			matchString = argv[optind];
			break;
		default:
			printf("INVALID OPTION -%c",option);
		}
		if(optind > lastOptIndex)
			lastOptIndex = optind;
	}
	if(argc > lastOptIndex + 1){ /* if there are no options but there is a filter expression */
		bpf_filter_expr = argv[lastOptIndex + 1];
	}
	/* find a capture device if not specified on command-line */
	if(dev == NULL && pcapFile == NULL){
		printf("\nNo device specified.\nFinding default device for capture. Please wait...");
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
					errbuf);
			exit(EXIT_FAILURE);
		}
		printf("\nCapturing on default interface: %s ",dev);
	}
	/* get network number and mask associated with capture device */
	if(dev != NULL){
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
					dev, errbuf);
			net = 0;
			mask = 0;
		}

		/* open capture device */
		handle = pcap_open_live(dev, SNAP_LEN, 1, -1, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}
	}else if(pcapFile != NULL){
		printf("\nReading packets from %s. Please wait...\n", pcapFile );
		handle = pcap_open_offline_with_tstamp_precision(pcapFile, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
	}
	/* make sure we're capturing on an Ethernet device*/
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (bpf_filter_expr != NULL && pcap_compile(handle, &bpfProg, bpf_filter_expr, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
				bpf_filter_expr, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (bpf_filter_expr != NULL && pcap_setfilter(handle, &bpfProg) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
				bpf_filter_expr, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* set callback function */
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	printf("\nCapture complete.\n");
	return 0;
}
