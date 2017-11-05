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
#include <signal.h>
#include <sys/prctl.h>

#define BUFFER_SIZE 1500

//TODO: We may not want to hard-code this
#define ICMP_SIZE 98

//TODO: This is currently hard coded; the project would never have more than 10 interfaces, but this is probably bad practice.
#define NUM_INTERFACE 10


//This was taken from the internet
struct __attribute__((packed)) arp_header {
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
	int packet_socket;
};

struct Route {
	int valid;
	unsigned char sourceIp[4];
	int numBytes;
	int hasIntermediateIp;
	unsigned char destIp[4];
	char * interfaceName;
};


//Headers:
struct Route handleForwarding(char buf[BUFFER_SIZE], struct Interface interface, struct Route routingTable[5]);
void handleArpRequest(char buf[BUFFER_SIZE], struct Interface interface);
void handleICMPRequest(char buf[BUFFER_SIZE], struct Interface interface);

void addIpHeader(unsigned char * buf, unsigned char sourceIp[4], unsigned char destIp[4]);
void addEthernetHeader(unsigned char * buf, unsigned char dest[6], unsigned char src[6], int ethType);
void addICMPHeader(unsigned char * buf, char * data, char id[2], char seq[2]);
void addArpResponseHeader(unsigned char * buf, unsigned char sourceMac[6], unsigned char destMac[6], 		unsigned char sourceIp[4], unsigned char destIp[4], int arpOp);
void buildArpRequest(unsigned char * buf, struct Interface interface, struct Route route);

void createIPArray(unsigned char * buffer, char * ip);

unsigned int calculateChecksum(unsigned char * buffer, int size);

void processForwardingTable(FILE *file, struct Route routingTable[5]);

struct Interface getInterfaceFromName(char * name, struct Interface interfaces[NUM_INTERFACE]);



int main(int argc, char ** argv) {
	if (argc != 2) {
		printf("You need to specify a routing table for this router.\n");
		return 0;
	}

	FILE *file = fopen(argv[1], "r");
	if (file == NULL) {
		printf("Invalid file.\n");
		return 0;
	}

	struct Route routingTable[5];
	processForwardingTable(file, routingTable);

	int i;
	printf("Routing Table: \n");
	for (i = 0; i <= 5; i++) {
		if (routingTable[i].valid == 0) {
			continue;
		}
		printf("\tinterfaceName: %s\n", routingTable[i].interfaceName);
		printf("\tsourceIp: %02x %02x %02x %02x\n", routingTable[i].sourceIp[0], routingTable[i].sourceIp[1], routingTable[i].sourceIp[2], routingTable[i].sourceIp[3]);
		printf("\tnumBytes: %d\n", routingTable[i].numBytes);
		printf("\thasIntermediateIp: %d\n", routingTable[i].hasIntermediateIp);
		printf("\tdestIp: %02x %02x %02x %02x\n", routingTable[i].destIp[0], routingTable[i].destIp[1], routingTable[i].destIp[2], routingTable[i].destIp[3]);
		printf("\n");
	}
	printf("\n");

	srand(time(NULL));

	struct Interface myInterface;

	struct Interface interfaces[NUM_INTERFACE];
	//int i;
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
					interfaces[i].packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
					printf("Creating Socket on interface %s\n", tmp->ifa_name);
					if(bind(interfaces[i].packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1){
						perror("bind");
					}
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
						interfaces[i].packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
						printf("Creating Socket on interface %s\n", tmp->ifa_name);
						if(bind(interfaces[i].packet_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1){
							perror("bind");
						}
						break;
					}
				}
			}
		}
	}

	for (i = 0; i < NUM_INTERFACE; i++) {
		if (interfaces[i].valid == 1) {
			printf("\nInformation for interface %s:\n", interfaces[i].name);
			printf("\tMAC Address is: %02x:%02x:%02x:%02x:%02x:%02x \n", interfaces[i].macAddress[0], interfaces[i].macAddress[1], interfaces[i].macAddress[2], interfaces[i].macAddress[3], interfaces[i].macAddress[4], interfaces[i].macAddress[5]);
			printf("\tIP Address is: %d.%d.%d.%d (%02x %02x %02x %02x)\n", interfaces[i].ipAddress[0], interfaces[i].ipAddress[1], interfaces[i].ipAddress[2], interfaces[i].ipAddress[3], interfaces[i].ipAddress[0], interfaces[i].ipAddress[1], interfaces[i].ipAddress[2], interfaces[i].ipAddress[3]);
			printf("\tPacket Socket is: %d \n\n", interfaces[i].packet_socket);


			//Handle Threading:
			if (strcmp(interfaces[i].name, "lo") == 0) {
				continue;
			}

			pid_t pid = fork();
			if (pid == 0) {
				prctl(PR_SET_PDEATHSIG, SIGHUP);
				myInterface = interfaces[i];
				break;
			}
		}
	}

	//free the interface list when we don't need it anymore
	//freeifaddrs(ifaddr);

	printf("Ready to recieve now\n");
	int waitingToForward = 0;
	while (1) {
		char buf[BUFFER_SIZE];
		char savedPacket[BUFFER_SIZE];
		struct sockaddr_ll recvaddr;
		int recvaddrlen = sizeof(struct sockaddr_ll);
		int n = recvfrom(myInterface.packet_socket, buf, BUFFER_SIZE, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
		if(recvaddr.sll_pkttype==PACKET_OUTGOING)
			continue;

		//start processing all others
		if (n != -1) {
			printf("Got a %d byte packet\n", n);
		} else {
			continue;
		}


		//Check if arp response
		unsigned char* arphead = buf + 14;
		struct arp_header *arpHeader = (struct arp_header *)arphead;

		if (ntohs(arpHeader->arp_op) == 0x02) {
			printf("Got an arp response.\n");
			printf("The MAC Address is %02x:%02x:%02x:%02x:%02x:%02x\n", arpHeader->arp_sha[0], arpHeader->arp_sha[1], arpHeader->arp_sha[2], arpHeader->arp_sha[3], arpHeader->arp_sha[4], arpHeader->arp_sha[5]);
			continue;
		}

		//Handle forwarding
		struct Route route = handleForwarding(buf, myInterface, routingTable);
		if (route.valid == 1) {
			struct Interface routeInterface = getInterfaceFromName(route.interfaceName, interfaces);
			printf("Going to build arp for interface %s\n", route.interfaceName);
			buildArpRequest(buf, routeInterface, route);
			continue;
		}
		
		//Handle any arp requests
		handleArpRequest(buf, myInterface);

		//Handle any ICMP requests
		handleICMPRequest(buf, myInterface);
	}

	//exit
	return 0;
}


//********************************************************************************************************
//***********************************************  Forwarding  *******************************************
//********************************************************************************************************

//Returns 1 if forwarded, 0 if not forwarded, 2 if waiting for arp
struct Route handleForwarding(char buf[BUFFER_SIZE], struct Interface interface, struct Route routingTable[5]) {
	int i = 0;
	int didForward;
	unsigned char* ethhead = (unsigned char*) buf;
	struct ethhdr *ethernetHeader = (struct ethhdr *) ethhead;

	unsigned char * ipHead = (unsigned char *) buf + 14;
	struct iphdr * ipHeader = (struct iphdr *) ipHead;

	unsigned char destIp[4];
	destIp[3] = ipHeader->daddr >> 24;
	destIp[2] = ipHeader->daddr >> 16;
	destIp[1] = ipHeader->daddr >> 8;
	destIp[0] = ipHeader->daddr;

	struct Route route = {.valid = 0};

	int equal = 1;
	for (i = 0; i < 4; i++) {
		equal &= destIp[i] == interface.ipAddress[i];
	}

	printf("Is destIp our ip? %d\n", equal);
	if (equal) {
		return route;
	}

	int j;
	for (i = 0; i < 5; i++) {
		if (routingTable[i].valid == 1) {
			int equal = 1;
			for (j = 0; j < (routingTable[i].numBytes / 8); j++) {
				equal &= destIp[j] == routingTable[i].sourceIp[j];
			}

			if (equal) {
				printf("We found a route.\n");
				route = routingTable[i];
				break;
			}
		}
	}

	return route;
}


//********************************************************************************************************
//***********************************************  ICMP Functions  ***************************************
//********************************************************************************************************
void handleICMPRequest(char buf[BUFFER_SIZE], struct Interface interface) {
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

		addEthernetHeader(buffer, ethernetHeader->h_source, interface.macAddress, 0x0800);
		addIpHeader(buffer, sourceIp, destIp);
		addICMPHeader(buffer, data, id, seq);

		printf("Sending ICMP Response. \n");

		send(interface.packet_socket, buffer, ICMP_SIZE, 0);
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
}


//********************************************************************************************************
//********************************************  ARP Functions  *******************************************
//********************************************************************************************************
void handleArpRequest(char buf[BUFFER_SIZE], struct Interface interface) {
	int i = 0;

	//Get ethernet header from the buffer
	unsigned char* ethhead = (unsigned char*) buf;
	struct ethhdr *ethernetHeader = (struct ethhdr *) ethhead;

	if (ntohs(ethernetHeader->h_proto) == ETH_P_ARP) {

		//Get arp header from the buffer if we're an arp packet
		unsigned char* arphead = buf + 14;
		struct arp_header *arpHeader = (struct arp_header *)arphead;

		int equal = 1;
		for (i = 0; i < 4; i++) {
			equal &= arpHeader->arp_dpa[i] == interface.ipAddress[i];
		}

		if (ntohs(arpHeader->arp_op) == ARPOP_REQUEST && equal) {
			printf("Got an arp request.\n");

			unsigned char buffer[42];
			for (i = 0; i < 42; i++) {
				buffer[i] = 0;
			}

			addEthernetHeader(buffer, ethernetHeader->h_source, interface.macAddress, 0x0806);
			addArpResponseHeader(buffer, interface.macAddress, arpHeader->arp_sha, arpHeader->arp_dpa, arpHeader->arp_spa, 0x02);

			printf("Sending arp response. \n");
			send(interface.packet_socket, buffer, 42, 0);
		}
	}
}

void buildArpRequest(unsigned char * buf, struct Interface interface, struct Route route) {
	unsigned char* ethhead = (unsigned char*) buf;
	struct ethhdr *ethernetHeader = (struct ethhdr *) ethhead;

	unsigned char * ipHead = (unsigned char *) buf + 14;
	struct iphdr * ipHeader = (struct iphdr *) ipHead;

	unsigned char buffer[42];
	int i;
	for (i = 0; i < 42; i++) {
		buffer[i] = 0;
	}

	unsigned char ethDestMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned char arpDestMac[6] = {0, 0, 0, 0, 0, 0};

	unsigned char destIp[4];
	if (route.hasIntermediateIp == 1) {
		memcpy(destIp, route.destIp, 4);
	} else {
		destIp[3] = ipHeader->daddr >> 24;
		destIp[2] = ipHeader->daddr >> 16;
		destIp[1] = ipHeader->daddr >> 8;
		destIp[0] = ipHeader->daddr;
	}

	addEthernetHeader(buffer, ethDestMac, interface.macAddress, 0x0806);
	addArpResponseHeader(buffer, interface.macAddress, arpDestMac, interface.ipAddress, destIp, 0x01);

	printf("Sending arp request with data:\n");
	for (i = 0; i < 42; i++) {
		printf("%02x ", buffer[i]);
	}
	printf("\n");
	send(interface.packet_socket, buffer, 42, 0);
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
}

void addArpResponseHeader(unsigned char * buf, unsigned char sourceMac[6], unsigned char destMac[6], unsigned char sourceIp[4], unsigned char destIp[4], int arpOp) {
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

	arpHeader->arp_op = htons(arpOp);
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
}

void createIPArray(unsigned char * buffer, char * ip) {
	char * token;
	int i = 0;
	while ((token = strsep(&ip, ".")) != NULL) {
		buffer[i] = (unsigned char)atoi(token);
		i++;
	}
}


//***************************************************************************
//********************* Helper Functions ************************************
//***************************************************************************
unsigned int calculateChecksum(unsigned char * buffer, int size) {
	unsigned int checksum = 0;
	int i;

	for (i = 0; i < size; i += 2) {
		checksum += ((buffer[i] << 8) + buffer[i + 1]);
	}

	checksum = (checksum >> 16) + checksum;
	return (unsigned int)~checksum;
}

struct Interface getInterfaceFromName(char * name, struct Interface interfaces[NUM_INTERFACE]) {
	struct Interface NULL_STRUCT = {.valid = 0};	
	int i;
	for (i = 0; i < NUM_INTERFACE; i++) {
		if (strcmp(name, interfaces[i].name) == 0) {
			return interfaces[i];
		}
	}
	return NULL_STRUCT;
}

struct Interface getInterfaceFromIp(unsigned char ip[4], struct Interface interfaces[NUM_INTERFACE]) {
	struct Interface NULL_STRUCT = {.valid = 0};	
	int i, j;
	for (i = 0; i < NUM_INTERFACE; i++) {
		int equal = 1;
		for (j = 0; j < 4; j++) {
			equal &= interfaces[i].ipAddress[j] == ip[j];
		}
		if (equal) {
			return interfaces[i];
		}
	}
	return NULL_STRUCT;
}

struct Interface getInterfaceFromMac(unsigned char mac[6], struct Interface interfaces[NUM_INTERFACE]) {
	struct Interface NULL_STRUCT = {.valid = 0};
	int i, j;
	for (i = 0; i < NUM_INTERFACE; i++) {
		int equal = 1;
		for (j = 0; j < 6; j++) {
			equal &= interfaces[i].macAddress[j] == mac[j];
		}
		if (equal) {
			return interfaces[i];
		}
	}
	return NULL_STRUCT;
}

void processForwardingTable(FILE *file, struct Route routingTable[5]) {
	int i;
	for (i = 0; i <= 5; i++) {
		routingTable[i].valid = 0;
	}
	char line[256];
	char * token;
	char * subToken;
	int currentRoute = 0;
	while(fgets(line, 256, file)) {
		int i = 0;
		char * lineCpy = line;
		routingTable[currentRoute].valid = 1;
		while ((token = strsep(&lineCpy, " ")) != NULL) {
			int j = 0;
			if (i == 0) {
				while ((subToken = strsep(&token, "/")) != NULL) {
					if (j == 0) {
						unsigned char tempIp[4];
						createIPArray(tempIp, subToken);
						memcpy(routingTable[currentRoute].sourceIp, tempIp, 4);
					} else {
						routingTable[currentRoute].numBytes = atoi(subToken);
					}
					j++;
				}
			}

			if (i == 1 && strcmp(token, "-") == 0) {
				printf("i is 1, token is -, sanity: %s\n", token);
				routingTable[currentRoute].hasIntermediateIp = 0;
			} else if (i == 1) {
				routingTable[currentRoute].hasIntermediateIp = 1;
				unsigned char tempIp[4];
				createIPArray(tempIp, token);
				printf("i is 1, token is not -, sanity: %s\n", token);
				printf("Temp ip %02x %02x %02x %02x\n", tempIp[0], tempIp[1], tempIp[2], tempIp[3]);
				memcpy(routingTable[currentRoute].destIp, tempIp, 4);
			}

			if (i == 2) {
				routingTable[currentRoute].interfaceName = (char *)malloc(strlen(token) - 1);
				strncpy(routingTable[currentRoute].interfaceName, token, strlen(token) - 1);
			}
			i++;
		}
		currentRoute++;
	}
	fclose(file);
}















