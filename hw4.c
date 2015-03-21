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

uint8_t solution[1500];
int solutionBytes;

uint8_t soaSolution[1500];
int soaBytes;

uint8_t cnameSolution[1500];
int cnameBytes;

//  Recursive function that resolves hostname's address
char *recursiveResolver(char *hostname, char *nameserver);

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

char *checkFields(char *hostname, uint8_t inputbuf[], int recvCount, uint8_t rectypeFlag)
{
   // parse the response to get our answer
    struct dns_hdr *ans_hdr=(struct dns_hdr*)inputbuf;
 
    uint8_t *answer_ptr = inputbuf + sizeof(struct dns_hdr);
     
    // now answer_ptr points at the first question. 
    int question_count = ntohs(ans_hdr->q_count);
    int answer_count = ntohs(ans_hdr->a_count);
    int auth_count = ntohs(ans_hdr->auth_count);
    int other_count = ntohs(ans_hdr->other_count);
 
    // skip past all questions
    int q;
    for(q=0;q<question_count;q++) {
        char string_name[255];
        memset(string_name,0,255);
        int size=from_dns_style(inputbuf,answer_ptr,string_name);
        answer_ptr+=size;
        answer_ptr+=4; //2 for type, 2 for class
    }
 
    int a;
    int got_answer=0;
 
    // now answer_ptr points at the first answer. loop through
    // all answers in all sections
    for(a=0;a<answer_count+auth_count+other_count;a++) {
        // first the name this answer is referring to 
        char string_name[255];
        int dnsnamelen=from_dns_style(inputbuf,answer_ptr,string_name);
        answer_ptr += dnsnamelen;
 
        // then fixed part of the RR record
        struct dns_rr* rr = (struct dns_rr*)answer_ptr;
        answer_ptr+=sizeof(struct dns_rr);
 
        const uint8_t RECTYPE_A=1;
        const uint8_t RECTYPE_NS=2;
        const uint8_t RECTYPE_CNAME=5;
        const uint8_t RECTYPE_SOA=6;
        const uint8_t RECTYPE_PTR=12;
        const uint8_t RECTYPE_AAAA=28;
 
        if (a < answer_count+auth_count+other_count) {}
            // printf("%s checked of type %d\n", string_name, htons(rr->type));
 
        if(htons(rr->type)==RECTYPE_A && rectypeFlag == RECTYPE_A) {
            if (strcmp(string_name, hostname) == 0) {               
                solutionBytes = dnsnamelen + sizeof(struct dns_rr) + htons(rr->datalen);             
                memcpy(solution,answer_ptr - sizeof(struct dns_rr) - dnsnamelen, solutionBytes);
                return inet_ntoa(*((struct in_addr *)answer_ptr));
            }
            char *s = recursiveResolver(hostname, inet_ntoa(*((struct in_addr *)answer_ptr)));
            if (s != 0) return s;
            got_answer=1;
            // forward response
            int a_len=from_dns_style(inputbuf,answer_ptr,hostname);
        }
        // NS record
        else if(htons(rr->type)==RECTYPE_NS && rectypeFlag == RECTYPE_NS) {
            char ns_string[255];
            int ns_len=from_dns_style(inputbuf,answer_ptr,ns_string);
            if(debug)
                printf("The name %s can be resolved by NS: %s\n",
                             string_name, ns_string);
            char *s = recursiveResolver(ns_string, "198.41.0.4");
            if (s != 0) {
                char * s1 = recursiveResolver(hostname, s);
                if (s1 != 0) return s1;     
            }
            got_answer=1;
            // forward response
        }
        // CNAME record
        else if(htons(rr->type)==RECTYPE_CNAME) {        
            char ns_string[255];
            int ns_len=from_dns_style(inputbuf,answer_ptr,ns_string);
 
            if (strcmp(string_name, hostname) == 0) {   
                char *s = recursiveResolver(ns_string, "198.41.0.4");
                if (s != 0) {           
                    cnameBytes = dnsnamelen + sizeof(struct dns_rr) + htons(rr->datalen);               
                    memcpy(cnameSolution,answer_ptr - sizeof(struct dns_rr) - dnsnamelen, cnameBytes);
                    return s;
                }       
            }               
            if(debug)
                printf("The name %s is also known as %s.\n", string_name, ns_string);                               
            got_answer=1;
        }
        // PTR record
        else if(htons(rr->type)==RECTYPE_PTR) {
            char ns_string[255];
            int ns_len=from_dns_style(inputbuf,answer_ptr,ns_string);
            printf("The host at %s is also known as %s.\n",
                         string_name, ns_string);                               
            got_answer=1;
        }
        // SOA record
        else if(htons(rr->type)==RECTYPE_SOA) {
 
            /*copy soa*/
            soaBytes = dnsnamelen + sizeof(struct dns_rr) + htons(rr->datalen);             
            memcpy(soaSolution,answer_ptr - sizeof(struct dns_rr) - dnsnamelen, soaBytes);
            //return 0;
            if(debug)
                printf("Ignoring SOA record\n");
        }
        // AAAA record
        else if(htons(rr->type)==RECTYPE_AAAA)  {
            if(debug)
                printf("Ignoring IPv6 record\n");
        }
        else {
            if(debug)
                printf("got unknown record type %hu\n",htons(rr->type));
        } 
 
        answer_ptr+=htons(rr->datalen);
    }
    return (char*)0;

}

char *recursiveResolver(char *hostname, char *nameserver)
{
    // using a constant name server address for now.
    in_addr_t nameserver_addr=inet_addr(nameserver);
     
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("Creating socket failed: ");
        exit(1);
    }
     
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 300000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
            perror("Error");
    }
 
    // construct the query message
    uint8_t query[1500];
    int query_len=construct_query(query,1500,hostname);
 
    struct sockaddr_in addr;    // internet socket address data structure
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53); // port 53 for DNS
    addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)
     
    int send_count = sendto(sock, query, query_len, 0, (struct sockaddr*)&addr,sizeof(addr));
    if(send_count<0) { perror("Send failed");    exit(1); }  
 
    // await the response 
    uint8_t inputbuf[1500];
    int recvCount;
    if ((recvCount = recv(sock,inputbuf,1500,0)) < 0) {
        if ((recvCount = recv(sock,inputbuf,1500,0)) < 0) {
            if ((recvCount = recv(sock,inputbuf,1500,0)) < 0) {
                return 0;
            }
        }
    }
 
    shutdown(sock,SHUT_RDWR);
    close(sock);
 
    char *s = checkFields(hostname, inputbuf, recvCount, 1);
    if (s== 0) s = checkFields(hostname, inputbuf, recvCount, 2);
    return s;   // returns IP of hostname
	
}

int createDNSResponse(char *hostname, char *nameserver, char *dnsResponse)
{
	in_addr_t nameserver_addr=inet_addr(nameserver);
     
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("Creating socket failed: ");
        exit(1);
    }
     
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 300000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
            perror("Error");
    }
 
    // construct the query message
    uint8_t query[1500];
    int query_len=construct_query(query,1500,hostname);
 
    struct sockaddr_in addr;    // internet socket address data structure
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53); // port 53 for DNS
    addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)
     
    int send_count = sendto(sock, query, query_len, 0, (struct sockaddr*)&addr,sizeof(addr));
    if(send_count<0) { perror("Send failed");    exit(1); }
 
    // await the response 
    int recvCount;
    if ((recvCount = recv(sock,dnsResponse,1500,0)) < 0) {
        if ((recvCount = recv(sock,dnsResponse,1500,0)) < 0) {
            if ((recvCount = recv(sock,dnsResponse,1500,0)) < 0) {
                printf("CATASTROPHIC ERROR!\n");
                return 0;
            }
        }
    }
 
    return recvCount;

}

int main(int argc, char** argv)
{
    memset(solution, 0, 1500);
    memset(soaSolution, 0, 1500);
    memset(cnameSolution, 0, 1500);
 
    if(argc<2) {
        printf("Not enough arguements!\n");
        exit(1);
    }
    int PORTNUM = atoi(argv[1]);
    int n, sockfd, newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    bzero(&serv_addr,sizeof(serv_addr));
    bzero(&serv_addr,sizeof(cli_addr));
    char buffer[1500];
    bzero(buffer,1500);
    char hostname[1500];
 
    serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(PORTNUM);
 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
 
    const int       optVal = 1;
    const socklen_t optLen = sizeof(optVal);
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen) < 0) {
        perror("setsockopt"); 
        exit(EXIT_FAILURE);
    }
 
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)  {
            perror("bind");
            exit(EXIT_FAILURE);
    }
 
    listen(sockfd,5);
 
    clilen = sizeof(cli_addr);
    n = recvfrom(sockfd,buffer,1500,0,(struct sockaddr *)&cli_addr,&clilen);
    if (n < 0) error("ERROR reading from socket");
 
    in_addr_t tempIP= cli_addr.sin_addr.s_addr;
    char* endIP = inet_ntoa(*(struct in_addr *)&tempIP); /* gets client IP from DIG */
 
    unsigned short digPort = cli_addr.sin_port; // gets portnum DIG is using
 
    struct dns_hdr *ans_hdr = (struct  dns_hdr*)buffer;
 
    char dnsResponse[1500];
    memset(dnsResponse, 0, 1500);
 
    memcpy(dnsResponse, buffer, n); //holding onto question query for now
 
    uint16_t id = ans_hdr->id;
    uint16_t flags = ans_hdr->flags;
 
    uint8_t *answer_ptr = buffer + sizeof(struct dns_hdr);
 
    // now answer_ptr points at the first question. 
    int question_count = ntohs(ans_hdr->q_count);
    int answer_count = ntohs(ans_hdr->a_count);
    int auth_count = ntohs(ans_hdr->auth_count);
    int other_count = ntohs(ans_hdr->other_count);
 
    // read question section to get hostname
    int q = 0;
    for(q=0;q<question_count;q++) {
        char string_name[255];
        memset(string_name,0,255);
        int size=from_dns_style(buffer,answer_ptr,string_name);
        strcpy(hostname, string_name);
        answer_ptr+=size;
        answer_ptr+=4; //2 for type, 2 for class
    }
 
    char * ipAddress = recursiveResolver(hostname, "198.41.0.4");
    printf("The hostname %s resolves to IP: %s\n", hostname, ipAddress);

    struct dns_hdr *response_hdr = (struct  dns_hdr*)buffer;
    if (ipAddress != 0) {
        if (cnameBytes != 0) {
            memcpy(answer_ptr, cnameSolution, cnameBytes);
            answer_ptr += cnameBytes;      
        }
         
        memcpy(answer_ptr, solution, solutionBytes);
        response_hdr->a_count = cnameBytes==0 ? htons(1) : htons(2);
        response_hdr->flags = htons(0x8000);
        answer_ptr += solutionBytes;
    }
    if (ipAddress == 0) {
        response_hdr->a_count = htons(0);
        response_hdr->flags = htons(0x8003);
        memcpy(answer_ptr, soaSolution, soaBytes);
        response_hdr->auth_count = htons(1);
        answer_ptr += soaBytes;
    }
         
    sendto(sockfd,buffer,answer_ptr-(uint8_t *)buffer,0,(struct sockaddr *)&cli_addr,sizeof(cli_addr));
    if (n < 0) 
            error("ERROR in sendto");
 
    close(newsockfd);
    close(sockfd);
 
    return 0;
}
