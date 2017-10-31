/**
 * CIS 457
 * Project 3
 * Fall, 2017
 * Authors: David Lamar, Taylor Cargill
 */

#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1500

//TODO: We may not want to hard-code this
#define ICMP_SIZE 98

//TODO: This is currently hard coded; the project would never have more than 10 interfaces, but this is probably bad practice.
#define NUM_INTERFACE 10


//This was taken from the internet; it's been modified to be in the correct order
struct __attribute__((packed)) arp_header
{
        unsigned short arp_hd;
        unsigned short arp_pr;
        unsigned char arp_hdl;
        unsigned char arp_prl;
        unsigned short arp_op;
        unsigned char arp_sha[6];
        unsigned char arp_spa[4];
	unsigned char arp_dha[6];
        unsigned char arp_dpa[4];

	//SHA is sender mac
	//spa is sender ip
	//DHA = target mac
	//dpa = target ip
};

struct Interface {
	int valid;
	char * name;
	unsigned char macAddress[6];
	unsigned char ipAddress[4];
};


//Headers:
void handleArpRequest(char buf[BUFFER_SIZE], unsigned char myMac[6], unsigned char myIp[4], int packet_socket);
void handleICMPRequest(char buf[BUFFER_SIZE], unsigned char myMac[6], unsigned char sourceIp[4], int packet_socket);

void addIpHeader(unsigned char * buf, unsigned char sourceIp[4], unsigned char destIp[4]);
void addEthernetHeader(unsigned char * buf, unsigned char dest[6], unsigned char src[6], int ethType);
void addICMPHeader(unsigned char * buf, char * data, char id[2], char seq[2]);
void addArpResponseHeader(unsigned char * buf, unsigned char sourceMac[6], unsigned char destMac[6], unsigned char senderIp[4], unsigned char destIp[4]);

unsigned int calculateChecksum(unsigned char * buffer, int size);

void createIPArray(unsigned char * buffer, char * ip);



int main() {
	srand(time(NULL));
	int packet_socket;

	unsigned char myMac[6];
	unsigned char myIp[4];

	struct Interface interfaces[NUM_INTERFACE];
	int i;
		for (i = 0; i < 6; i++) { myMac[i] = 0; }
	for (i = 0; i < NUM_INTERFACE; i++) { interfaces[i].valid = 0; }

	//get list of interfaces (actually addresses)
	struct ifaddrs *ifaddr, *tmp;
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return 1;
	}

	//have the list, loop over the list
	for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
		//IPV4
		if (tmp->ifa_addr->sa_family == AF_INET) {
            		char * ipAddress = inet_ntoa(((struct sockaddr_in *) tmp->ifa_addr)->sin_addr);

			int i;
			int found = 0;
			//Check if interface is in the array
			for (i = 0; i < NUM_INTERFACE; i++) {
				if (interfaces[i].valid == 1 && strcmp(tmp->ifa_name, interfaces[i].name) == 0) {
					found = 1;
					createIPArray(interfaces[i].ipAddress, ipAddress);
					break;
				}
			}

			if (found == 0) {
				for (i = 0; i < NUM_INTERFACE; i++) {
					if (interfaces[i].valid == 0) {
						interfaces[i].valid = 1;
						interfaces[i].name = (char *) malloc(strlen(tmp->ifa_name) + 1);
						strcpy(interfaces[i].name, tmp->ifa_name);
						createIPArray(interfaces[i].ipAddress, ipAddress);
						break;
					}
				}
			}
		}


		//Check if this is a packet address, there will be one per
		//interface.  There are IPv4 and IPv6 as well, but we don't care
		//about those ICMP_SIZEfor the purpose of enumerating interfaces. We can
		//use the AF_INET addresses in this list for example to get a list
		//of our own IP addresses
		//MAC
		if (tmp->ifa_addr->sa_family == AF_PACKET) {
			printf("Interface: %s\n", tmp->ifa_name);
			
			struct sockaddr_ll *s = (struct sockaddr_ll*) tmp->ifa_addr;
			unsigned char macAddress[6];
			memcpy(macAddress, s->sll_addr, 6);

			int i;
			int found = 0;
			//Check if interface is in the array
			for (i = 0; i < NUM_INTERFACE; i++) {
				if (interfaces[i].valid == 1 && strcmp(tmp->ifa_name, interfaces[i].name) == 0) {
					found = 1;
					memcpy(interfaces[i].macAddress, macAddress, 6);
					break;
				}
			}

			if (found == 0) {
				for (i = 0; i < NUM_INTERFACE; i++) {
					if (interfaces[i].valid == 0) {
						interfaces[i].valid = 1;
						interfaces[i].name = (char *)malloc(strlen(tmp->ifa_name) + 1);
						strcpy(interfaces[i].name, tmp->ifa_name);
						memcpy(interfaces[i].macAddress, macAddress, 6);
						break;
					}
				}
			}

			//create a packet socket on interface r?-eth1
			//TODO: We need to open connections on the other interfaces as well.
			//TODO: May need to thread in order to handle this "It's a good idea"
			if (!strncmp(&(tmp->ifa_name[3]), "eth1", 4)) {
				printf("Creating Socket on interface %s\n", tmp->ifa_name);
				//create a packet socket
				//AF_PACKET makes it a packet socket
				//SOCK_RAW makes it so we get the entire packet
				//could also use SOCK_DGRAM to cut off link layer header
				//ETH_P_ALL indicates we want all (upper layer) protocols
				//we could specify just a specific one
				packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				if (packet_socket < 0) {
					perror("socket");
					return 2;
				}
				//Bind the socket to the address, so we only get packets
				//recieved on this specific interface. For packet sockets, the
				//address structure is a struct sockaddr_ll (see the man page
				//for "packet"), but of course bind takes a struct sockaddr.
				//Here, we can use the sockaddr we got from getifaddrs (which
				//we could convert to sockaddr_ll if we needed to)
				if(bind(packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1){
					perror("bind");
				}
			}
		}
	}

	for (i = 0; i < NUM_INTERFACE; i++) {
		if (interfaces[i].valid == 1) {
			printf("\nInformation for interface %s:\n", interfaces[i].name);
			printf("\tMAC Address is: %02x:%02x:%02x:%02x:%02x:%02x \n", interfaces[i].macAddress[0], interfaces[i].macAddress[1], interfaces[i].macAddress[2], interfaces[i].macAddress[3], interfaces[i].macAddress[4], interfaces[i].macAddress[5]);
			printf("\tIP Address is: %d.%d.%d.%d (%02x %02x %02x %02x)\n\n", interfaces[i].ipAddress[0], interfaces[i].ipAddress[1], interfaces[i].ipAddress[2], interfaces[i].ipAddress[3], interfaces[i].ipAddress[0], interfaces[i].ipAddress[1], interfaces[i].ipAddress[2], interfaces[i].ipAddress[3]);

			if (strncmp(&(interfaces[i].name[3]), "eth1", 4) == 0) {
				printf("Set myMac\n");
				memcpy(myMac, interfaces[i].macAddress, 6);
				memcpy(myIp, interfaces[i].ipAddress, 4);
			}
		}
	}

	//free the interface list when we don't need it anymore
	//freeifaddrs(ifaddr);

	//loop and recieve packets. We are only looking at one interface,
	//for the project you will probably want to look at more (to do so,
	//a good way is to have one socket per interface and use select to
	//see which ones have data)
	printf("Ready to recieve now\n");
	while (1) {
		char buf[BUFFER_SIZE];
		struct sockaddr_ll recvaddr;
		int recvaddrlen = sizeof(struct sockaddr_ll);
		//we can use recv, since the addresses are in the packet, but we
		//use recvfrom because it gives us an easy way to determine if
		//this packet ICMP_SIZEis incoming or outgoing (when using ETH_P_ALL, we
		//see packets in both directions. Only outgoing can be seen when
		//using a packet socket with some specific protocol)
		int n = recvfrom(packet_socket, buf, BUFFER_SIZE, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
		//ignore outgoing packets (we can't disable some from being sent
		//by the OS automatically, for example ICMP port unreachable
		//messages, so we will just ignore them here)
		if(recvaddr.sll_pkttype==PACKET_OUTGOING)
			continue;

		//start processing all others
		if (n != -1) {
			printf("Got a %d byte packet\n", n);
		}

    
		//what else to do is up to you, you can send packets with send,
		//just like we used for TCP sockets (or you can use sendto, but it
		//is not necessary, since the headers, including all addresses,
		//need to be in the buffer you are sending)

		//Handle any arp requests
		handleArpRequest(buf, myMac, myIp, packet_socket);

		//Handle any ICMP requests
		handleICMPRequest(buf, myMac, myIp, packet_socket);
	}

	//exit
	return 0;
}


//********************************************************************************************************
//***********************************************  ICMP Functions  ***************************************
//********************************************************************************************************
void handleICMPRequest(char buf[BUFFER_SIZE], unsigned char myMac[6], unsigned char sourceIp[4], int packet_socket) {
	int i = 0;
	unsigned char* ethhead = (unsigned char*) buf;
	struct ethhdr *ethernetHeader = (struct ethhdr *) ethhead;

	unsigned char * ipHead = (unsigned char *) buf + 14;
	struct iphdr * ipHeader = (struct iphdr *) ipHead;

	unsigned char * icmpHead = (unsigned char *) buf + 14 + sizeof(struct iphdr);
	struct icmphdr * icmpHeader = (struct icmphdr *) icmpHead;

	//0x08 is an echo request
	if (icmpHeader->type == 0x8) {
		printf("We got an ICMP echo request\n");
		
		unsigned char buffer[ICMP_SIZE];
		for (i = 0; i < ICMP_SIZE; i++) {
			buffer[i] = 0;
		}

		unsigned char destIp[4];
		destIp[3] = ipHeader->saddr >> 24;
		destIp[2] = ipHeader->saddr >> 16;
		destIp[1] = ipHeader->saddr >> 8;
		destIp[0] = ipHeader->saddr;

		unsigned char sourceIp[4];
		sourceIp[3] = ipHeader->daddr >> 24;
		sourceIp[2] = ipHeader->daddr >> 16;
		sourceIp[1] = ipHeader->daddr >> 8;
		sourceIp[0] = ipHeader->daddr;

		int sub = (14 + 20 + 8);
		int dataSize = ICMP_SIZE - sub;
		char data[dataSize];
		for (i = 0; i < dataSize; i++) {
			data[i] = (buf + sub)[i];
		}

		char id[2];
		char seq[2];

		for (i = 0; i < 2; i++) {
			id[i] = buf[14 + 20 + 4 + i];
			seq[i] = buf[14 + 20 + 6 + i];
		}

		addEthernetHeader(buffer, ethernetHeader->h_source, myMac, 0x0800);
		addIpHeader(buffer, sourceIp, destIp);
		addICMPHeader(buffer, data, id, seq);

		printf("Sending ICMP Response. \n");

		send(packet_socket, buffer, ICMP_SIZE, 0);
	}
}

void addIpHeader(unsigned char * buf, unsigned char sourceIp[4], unsigned char destIp[4]) {
	int i;
	unsigned char * ipHead = (unsigned char *) buf + 14;
	struct iphdr * ipHeader = (struct iphdr *) ipHead;

	ipHeader->version = 0x4;
	ipHeader->ihl = 0x5;
	ipHeader->tos = 0;
	ipHeader->tot_len = htons(ICMP_SIZE - 14); 
	ipHeader->id = htons(rand());
	ipHeader->frag_off = 0;
	ipHeader->ttl = 64;
	ipHeader->protocol = 0x1;
	ipHeader->check = 0; //Set as 0 so we don't have junk bits

	for (i = 0; i < 4; i++) {
		buf[i + 14 + 12] = sourceIp[i];
		buf[i + 14 + 12 + 4] = destIp[i];
	}

	unsigned char * ipBuffer = (unsigned char *)ipHeader;
	for (i = 0; i < sizeof(struct iphdr); i++) {
		buf[i + 14] = ipBuffer[i];
	}

	unsigned int checksum = calculateChecksum(buf + 14, 20);
	buf[14 + 10] = checksum >> 8;
	buf[14 + 11] = checksum;

	printf("IP Header: ");
	for (i = 0; i < 20; i++) {
		printf("%02x ", buf[i + 14]);
	}
	printf("\n");
}

void addICMPHeader(unsigned char * buf, char * data, char id[2], char seq[2]) {
	int i;
	unsigned char * icmpHead = (unsigned char *) buf + 14 + sizeof(struct iphdr);
	struct icmphdr * icmpHeader = (struct icmphdr *) icmpHead;

	icmpHeader->type = 0;
	icmpHeader->code = 0;
	icmpHeader->checksum = 0;
	
	//put initial bytes into buffer
	unsigned char * icmpBuffer = (unsigned char *)icmpHeader;
	for (i = 0; i < 4; i++) {
		buf[i + 14 + sizeof(struct iphdr)] = icmpBuffer[i];
	}

	for (i = 0; i < 2; i++) {
		buf[i + 14 + sizeof(struct iphdr) + 4] = id[i];
		buf[i + 14 + sizeof(struct iphdr) + 6] = seq[i];
	}

	//Puts the data into the packet
	for (i = 14 + sizeof(struct iphdr) + 8; i < ICMP_SIZE; i++) {
		buf[i] = data[i - (14 + sizeof(struct iphdr) + 8)];
	}

	unsigned int checksum = calculateChecksum(buf + 14 + sizeof(struct iphdr), ICMP_SIZE - 14 - 20);
	buf[14 + sizeof(struct iphdr) + 2] = checksum >> 8;
	buf[14 + sizeof(struct iphdr) + 3] = checksum;

	printf("ICMP Header: ");
	for (i = 0; i < 98; i++) {
		printf("%02x ", buf[i + 14 + sizeof(struct iphdr)]);
	}
	printf("\n");
}

unsigned int calculateChecksum(unsigned char * buffer, int size) {
	unsigned int checksum = 0;
	int i;

	for (i = 0; i < size; i += 2) {
		checksum += ((buffer[i] << 8) + buffer[i + 1]);
	}

	checksum = (checksum >> 16) + checksum;
	return (unsigned int)~checksum;
}


//********************************************************************************************************
//********************************************  ARP Functions  *******************************************
//********************************************************************************************************

void handleArpRequest(char buf[BUFFER_SIZE], unsigned char myMac[6], unsigned char myIp[4], int packet_socket) {
	//Get ethernet header from the buffer
	int i = 0;
	unsigned char* ethhead = (unsigned char*) buf;
	struct ethhdr *ethernetHeader = (struct ethhdr *) ethhead;

	//Get arp header from the buffer if we're an arp packet
	if (ntohs(ethernetHeader->h_proto) == ETH_P_ARP) {
		unsigned char* arphead = buf + 14;
		struct arp_header *arpHeader = (struct arp_header *)arphead;

		if (ntohs(arpHeader->arp_op) == ARPOP_REQUEST) {
			printf("Got an arp request.\n");
			//TODO: Need to check if it's our IP address, otherwise we want to ignore.

			unsigned char buffer[42];
			for (i = 0; i < 42; i++) {
				buffer[i] = 0;
			}

			addEthernetHeader(buffer, ethernetHeader->h_source, myMac, 0x0806);
			addArpResponseHeader(buffer, myMac, arpHeader->arp_sha, arpHeader->arp_dpa, arpHeader->arp_spa);

			printf("Sending arp response; the buffer is: ");
			for (i = 0; i < 42; i++) {
				printf("%02x ", buffer[i]);
			}
			printf(" \n");

			send(packet_socket, buffer, 42, 0);
		}
	}
}

void addEthernetHeader(unsigned char * buf, unsigned char dest[6], unsigned char src[6], int ethType) {
	int i;
	unsigned char* ethhead = (unsigned char*) buf;
	struct ethhdr *ethernetHeader = (struct ethhdr *) ethhead;
	ethernetHeader->h_proto = htons(ethType);
	
	for (i = 0; i < 6; i++) {
		ethernetHeader->h_dest[i] = dest[i];
		ethernetHeader->h_source[i] = src[i]; 
	}


	unsigned char * ethernetBuffer = (unsigned char *)ethernetHeader;
	for (i = 0; i < sizeof(struct ethhdr); i++) {
		buf[i] = ethernetBuffer[i];
	}

	printf("Ethernet Header: ");
	for (i = 0; i < 14; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

void addArpResponseHeader(unsigned char * buf, unsigned char sourceMac[6], unsigned char destMac[6], unsigned char sourceIp[4], unsigned char destIp[4]) {
	int i;
	unsigned char* arphead = buf + 14;

	//SHA is sender mac
	//spa is sender ip
	//DHA = target mac
	//dpa = target ip

	struct arp_header *arpHeader = (struct arp_header *)arphead;

	arpHeader->arp_hd = htons(0x01);
	arpHeader->arp_pr = htons(0x800);
	arpHeader->arp_hdl = 0x6;
	arpHeader->arp_prl = 0x4;

	arpHeader->arp_op = htons(0x02);
	for (i = 0; i < 4; i++) {
		arpHeader->arp_spa[i] = sourceIp[i];
		arpHeader->arp_dpa[i] = destIp[i];
	}

	for (i = 0; i < 6; i++) {
		arpHeader->arp_sha[i] = sourceMac[i];
		arpHeader->arp_dha[i] = destMac[i];
	}

	unsigned char * arpHeaderBuffer = (unsigned char *)arpHeader;
	for (i = 0; i < sizeof(struct arp_header); i++) {
		buf[i + 14] = arpHeaderBuffer[i];
	}

	printf("Arp Header: ");
	for (i = 0; i < sizeof(struct arp_header); i++) {
		printf("%02x ", buf[i + 14]);
	}
	printf("\n");
}

void createIPArray(unsigned char * buffer, char * ip) {
	char * cpy = (char *) malloc(4);

	char * token;
	int i = 0;
	while ((token = strsep(&ip, ".")) != NULL && i < 4) {
		buffer[i] = (unsigned char)atoi(token);
		i++;
	}
}


















