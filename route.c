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

//TODO: This is currently hard coded; the project would never have more than 10 interfaces, but this is probably bad practice.
#define NUM_INTERFACE 10

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
};

struct Interface {
	int valid;
	char * name;
	unsigned char macAddress[6];
	unsigned char ipAddress[4];
};

void handleArpRequest(char buf[BUFFER_SIZE], unsigned char myMac[6], unsigned char myIp[4], int packet_socket);
void addEthernetHeader(unsigned char * buffer, unsigned char dest[6], unsigned char src[6]);
void addArpResponseHeader(unsigned char * buf, unsigned char sourceMac[6], unsigned char destMac[6], unsigned char senderIp[4], unsigned char destIp[4]);
void createIPArray(unsigned char * buffer, char * ip);

int main() {
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
		//about those for the purpose of enumerating interfaces. We can
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

			if (strncmp(&(interfaces[i].name[3]), "eth0", 4) == 0) {
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
		//this packet is incoming or outgoing (when using ETH_P_ALL, we
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

	}

	//exit
	return 0;
}

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

			//TODO: This used to be just char
			unsigned char buffer[42];
			for (i = 0; i < 42; i++) {
				buffer[i] = 0;
			}

			addEthernetHeader(buffer, ethernetHeader->h_source, myMac);
			addArpResponseHeader(buffer, myMac, arpHeader->arp_sha, myIp, arpHeader->arp_spa);

			printf("Sending arp response; the buffer is: ");
			for (i = 0; i < 42; i++) {
				printf("%02x ", buffer[i]);
			}
			printf(" \n");

			send(packet_socket, buffer, BUFFER_SIZE, 0);
		}
	}
}


void addEthernetHeader(unsigned char * buf, unsigned char dest[6], unsigned char src[6]) {
	//TODO: I think we're using the wrong ethernet header object. Should be ether_header
	int i;
	unsigned char* ethhead = (unsigned char*) buf;
	struct ethhdr *ethernetHeader = (struct ethhdr *) ethhead;
	ethernetHeader->h_proto = htons(0x806);
	
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

	arpHeader->arp_op = htons(ARPOP_REPLY);
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



void createArpResponse(char buffer[0]) {
	
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


















