#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include "dns.h"

static int debug=0, nameserver_flag=0;

// Function signature
int construct_query(uint8_t* query, int max_query, char* hostname);

int PORT = 53;

void usage() 
{
	printf("Usage: hw2 [-d] -i domain/ip_address\n\t-d: debug\n");
	exit(1);
}

char* findDNSServer(int x, char inputServers[x][20], int socket, char* hostname)
{
	int i;
	for (i = 0; i < x; i++)
	{
		// using a constant name server address for now.
		in_addr_t nameserver_addr = inet_addr(inputServers[i]);
	
		// construct the query message
		uint8_t query[1500];
		int query_len = construct_query(query, 1500, hostname);

		struct sockaddr_in addr; 	// internet socket address data structure
		//printf("Set up listening...\n");
		addr.sin_family = AF_INET;
		addr.sin_port = htons(53); // port 53 for DNS
		addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)
	
		int send_count = sendto(socket, query, query_len, 0, (struct sockaddr*)&addr,sizeof(addr));
		if(send_count < 0)
		{
			continue;
		}	

		// Set timer for receive
		struct timeval tv;

		// 5 second timeout
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(struct timeval));

		// await the response 
		uint8_t answerbuf[1500];
		int recv_count = recv(socket, answerbuf, 1500, 0);

		printf("Checking if %s is a valid root server...\n\n", inputServers[i]);

		if (recv_count > 0)
		{
			printf("Turns out %s is a valid root server!\n\n", inputServers[i]);

			shutdown(socket,SHUT_RDWR);
			close(socket);

			return inputServers[i];
		}
	}
	shutdown(socket,SHUT_RDWR);
	close(socket);
	
	
	printf("Error finding a valid DNS server from text file!");
		exit(1);
}

int* findNameServer(char* hostname, char* nameserver)
{
	/////////////////////////////////////////////////////////////
	// Create socket that will wait and listen for a dig request
	/////////////////////////////////////////////////////////////
	
	int sock_1;
	struct sockaddr_in sockAddrInfo;

	sock_1 = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_1 < 0)
	{
		printf("Error creating socket when waiting for a request...\nExiting...\n");
		exit(1);
	}

	sockAddrInfo.sin_family = AF_INET;
	sockAddrInfo.sin_addr.s_addr = INADDR_ANY;
	sockAddrInfo.sin_port = htons(53);

	int socketoptnum = 1;
	setsockopt(sock_1, SOL_SOCKET, SO_REUSEADDR, &socketoptnum, sizeof(socketoptnum));

	printf("Server waiting for connection...\n");
	if (bind(sock_1, (struct sockaddr *) &sockAddrInfo, sizeof(sockAddrInfo)) < 0)
	{
		printf("There was a bind error!\nExiting...\n");
		exit(1);
	}

	socklen_t addr_len;
	struct sockaddr_in cliaddr;
	int recv_bytes;
	uint8_t requestbuf[1500];

	addr_len = sizeof(cliaddr);
	if ((recv_bytes = recvfrom(sock_1, requestbuf, 1500, 0, (struct sockaddr *) &cliaddr, &addr_len)) == 0)
	{
		printf("Error receiving!\n");
		exit(1);
	}

	printf("Received data!\n");


	printf("\nDNS Request received from dig: \n");

	printf("Port: %i\n", ntohs(cliaddr.sin_port));
	printf("IP Address: %s\n", inet_ntoa(cliaddr.sin_addr));


	// Parse DNS request to get hostname
	struct dns_hdr *quest_hdr = (struct dns_hdr*) requestbuf;
	uint8_t *quest_ptr = requestbuf + sizeof(struct dns_hdr);
	
	int question_count_0 = ntohs(quest_hdr->q_count);

	char *dig_hostname;
	int q;
	for(q = 0; q < question_count_0; q++) 
	{
		char dig_hostname[255];
		memset(dig_hostname, 0, 255);
		int size = from_dns_style(requestbuf, quest_ptr, dig_hostname);

		printf("Hostname: %s\n\n", hostname);

	}

	/////////////////////////////////////////////////////////////////////////
	// Send received DNS request from dig to rootserver
	/////////////////////////////////////////////////////////////////////////

	int sock_2 = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_2 < 0)
	{
		printf("Error creating socket_2 that sends/receives data from rootserver\nExiting...\n");
		exit(1);
	}

	
	// Construct query to send to rootserver
	uint8_t rootQuery[1500];
	int rootQuery_len = construct_query(rootQuery, 1500, hostname);

	struct sockaddr_in response_addr;
	in_addr_t rootserver_addr = inet_addr(nameserver);

	response_addr.sin_family = AF_INET;
	response_addr.sin_port = htons(53);
	response_addr.sin_addr.s_addr = rootserver_addr;

	printf("Sending request to root server with folling information: \n");
	printf("Sending to port: %i\n", ntohs(response_addr.sin_port));
	printf("Sending to IP Address: %s\n\n", inet_ntoa(response_addr.sin_addr));

	printf("Attempting to send query to root server...\n");
	// Send DNS request to root server
	int rootserver_send_count = sendto(sock_2, rootQuery, rootQuery_len, 0, (struct sockaddr *) &response_addr, sizeof(response_addr));
	if (rootserver_send_count < 0)
	{
		printf("Sending dig DNS request to root server failed!\nExiting...\n");
		exit(1);
	}
	printf("Sent DNS request to rootserver!\n");

	// Set receive timeout
	struct timeval tv;

	// 10 second timeout
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sock_2, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(struct timeval));
	
	printf("\nWaiting for DNS response from rootserver: \n");

	// Await response from rootserver
	uint8_t answerbuf[1500];
	struct sockaddr_in serveraddr;
	socklen_t serveraddr_len;
	serveraddr_len = sizeof(serveraddr);

	int response_count = recv(sock_2, answerbuf, 1500, 0);
	if (response_count < 0)
	{
		printf("Error(or timeout) from receiving data from root server!\nExiting...\n");
		exit(1);
	}
	else
	{
		printf("Received some data from root server!: %i\n", response_count);
	}

	// Parse the DNS response we get from the root server
	struct dns_hdr *ans_hdr = (struct dns_hdr*) answerbuf;
	uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);
	
	// now answer_ptr points at the first question. 
	int question_count = ntohs(ans_hdr->q_count);
	int answer_count = ntohs(ans_hdr->a_count);
	int auth_count = ntohs(ans_hdr->auth_count);
	int other_count = ntohs(ans_hdr->other_count);


	// Skip questions
	int w;
	for(w = 0; w < question_count; w++) 
	{
		char string_name[255];
		memset(string_name, 0, 255);
		int size = from_dns_style(answerbuf, answer_ptr, string_name);
		answer_ptr += size;
		answer_ptr += 4; //2 for type, 2 for class

		//printf("Hostname: %s \n", string_name);
	}

	int a;
	int got_answer = 0;

	// Parse and print DNS response
	// now answer_ptr points at the first answer. loop through
	// all answers in all sections
	for(a = 0; a < answer_count + auth_count + other_count; a++) 
	{
		// first the name this answer is referring to 
		char string_name[255];
		int dnsnamelen=from_dns_style(answerbuf, answer_ptr, string_name);
		answer_ptr += dnsnamelen;

		// then fixed part of the RR record
		struct dns_rr* rr = (struct dns_rr*) answer_ptr;
		answer_ptr += sizeof(struct dns_rr);

		const uint8_t RECTYPE_A = 1;
		const uint8_t RECTYPE_NS = 2;
		const uint8_t RECTYPE_CNAME = 5;
		const uint8_t RECTYPE_SOA = 6;
		const uint8_t RECTYPE_PTR = 12;
		const uint8_t RECTYPE_AAAA = 28;
	
		// Answer field
		if(htons(rr->type)==RECTYPE_A) 
		{
			printf("ADDITIONAL FIELD: ");
			printf("The name %s resolves to IP addr: %s\n",
						 string_name,
						 inet_ntoa(*((struct in_addr *)answer_ptr)));
			got_answer=1;
		}
		// NS record
		else if(htons(rr->type)==RECTYPE_NS) 
		{
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
				
				printf("AUTHORITATIVE FIELD: ");
				printf("The name %s can be resolved by NS: %s\n",
							 string_name, ns_string);
					
			got_answer=1;
		}
		// CNAME record
		else if(htons(rr->type)==RECTYPE_CNAME) 
		{
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
				printf("CNAME FIELD: ");
				printf("The name %s is also known as %s.\n",
							 string_name, ns_string);
								
			got_answer=1;
		}
		// PTR record
		else if(htons(rr->type)==RECTYPE_PTR) 
		{
			printf("PTR FIELD: ");
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			printf("The host at %s is also known as %s.\n",
						 string_name, ns_string);								
			got_answer=1;
		}
		// SOA record
		else if(htons(rr->type)==RECTYPE_SOA) 
		{
			printf("SOA FIELD: ");
				printf("Ignoring SOA record\n");
		}
		// AAAA record
		else if(htons(rr->type)==RECTYPE_AAAA)  
		{
			printf("AAAA FIELD: ");
				printf("Ignoring IPv6 record\n");
		}
		else 
		{
			printf("UNKNOWN FIELD: ");
				printf("got unknown record type %hu\n",htons(rr->type));
		} 

		answer_ptr += htons(rr->datalen);
	}

	if(!got_answer) printf("Host %s not found.\n", hostname);

	shutdown(sock_2, SHUT_RDWR);
	close(sock_2);

}

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname) 
{
	memset(query, 0, max_query);

	in_addr_t rev_addr=inet_addr(hostname);
	if(rev_addr!=INADDR_NONE) {
		static char reverse_name[255];		
		sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
						(rev_addr&0xff000000)>>24,
						(rev_addr&0xff0000)>>16,
						(rev_addr&0xff00)>>8,
						(rev_addr&0xff));
		hostname=reverse_name;
	}

	// first part of the query is a fixed size header
	struct dns_hdr *hdr = (struct dns_hdr*)query;

	// generate a random 16-bit number for session
	uint16_t query_id = (uint16_t) (random() & 0xffff);
	hdr->id = htons(query_id);

	// set header flags to request recursive query
	hdr->flags = htons(0x0000);	
	// 1 question, no answers or other records
	hdr->q_count=htons(1);

	// add the name
	int query_len = sizeof(struct dns_hdr); 
	int name_len = to_dns_style(hostname,query+query_len);
	query_len += name_len; 
	
	// now the query type: A or PTR. 
	uint16_t *type = (uint16_t*)(query+query_len);
	if(rev_addr!=INADDR_NONE)
		*type = htons(12);
	else
		*type = htons(1);
	query_len+=2;

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
 
	return query_len;	
}

int main(int argc, char** argv)
{
	// Handle command-line arguments
	if(argc < 2)
	{
		usage();
	}
	
	char *hostname = 0;
	char *nameserver = 0;
	
	char *optString = "-d-n:-i:";
 	int opt = getopt( argc, argv, optString );
	
	while( opt != -1 ) 
	{
		switch( opt ) 
		{      
		case 'd':
			debug = 1; 
			break;
		case 'n':
			nameserver_flag = 1; 
			nameserver = optarg;
			break;	 		
		case 'i':
			hostname = optarg;
			break;	
		case '?':
			usage();
			exit(1);               
		default:
			usage();
			exit(1);
		}
		
		opt = getopt( argc, argv, optString );
	}
	
	// If the user has input no nameserver or hostname, throw an error	
	if(!nameserver || !hostname) 
	{
		usage();
		exit(1);
	}

	// Read from root-servers.txt
	FILE *fp = fopen("root-servers.txt", "r");
	char line[20];
	int rootCount = 0;

	// Max size of addresses for input file is 100
	char rootServers[100][20];
	if (fp == NULL)
	{
		printf("Could not find 'root-servers.txt' file in directory...\n");
		printf("Exiting...\n");
		exit(1);
	}

	while (fgets(line, 20, fp) != NULL)
	{
		sprintf(rootServers[rootCount], "%s", line);
		rootCount++;
	}
	
	// Prints out root servers as a sanity check
	printf("Addresses from text file: \n");
	int j;
	for (j = 0; j < rootCount; j++)
	{
		printf("%s", rootServers[j]);
	}
	printf("\n");

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) 
	{
		perror("Creating socket failed: ");
		exit(1);
	}

	// Find valid DNS server from list
	char *rootServer = findDNSServer(rootCount, rootServers, sock, hostname);
	in_addr_t nameserver_addr = inet_addr(rootServer);
	
	printf("Using address: %s", rootServer);

	//int* findNameserver(char* hostname, char* nameserver, int sock)
	findNameServer(hostname, rootServer);
}
