// Compile: gcc filename.c -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <string.h>
#include <errno.h>

// Headers
void prepareSender();
void prepareListener();
void appendToFile(char *data);
void fillList(const char *fileName);
void addToList(char* ip, char *wholeLine);

unsigned short csum(unsigned short *ptr,int nbytes);
unsigned short calculateUDPChecksum(void *iphdr, struct udphdr *udphdr, char *payload, int payloadlen);

struct dnshdr
{
 unsigned short id; // identification number

 unsigned char rd :1; // recursion desired
 unsigned char tc :1; // truncated message
 unsigned char aa :1; // authoritive answer
 unsigned char opcode :4; // purpose of message
 unsigned char qr :1; // query/response flag

 unsigned char rcode :4; // response code
 unsigned char cd :1; // checking disabled
 unsigned char ad :1; // authenticated data
 unsigned char z :1; // its z! reserved
 unsigned char ra :1; // recursion available

 unsigned short q_count; // number of question entries
 unsigned short ans_count; // number of answer entries
 unsigned short auth_count; // number of authority entries
 unsigned short add_count; // number of resource entries
};

struct listEntry {
 char ip[15];
 char wholeLine[256];
 struct listEntry *next;
 int isChecked;
 int id;
};

// Program variable.
int scanningActive = 1;
int listenPort = 25000;
char targetFileName[256];
int sendPPS = 25000;

struct listEntry *listBegin = NULL;
struct listEntry *listCur = NULL;
int listSize = 0;
int listChecked = 0;

// C Functions
int main (int argc, const char* argv[]) {
 if(argc < 4) {
  printf("DNS Recursivity Checker - by bitshock\n");
  printf("Usage: <source file> <output file> <send speed in pps>\n");
  printf("Note: The source file must have the IP address first on every line, followed by a space or tab.\n");
  
  return;
 }
 
 // Prepare arguments
 const char *sourceFile = argv[1];
 const char *targetFile = argv[2];
 sendPPS = atoi(argv[3]);
 
 // Set target file.
 memcpy(&targetFileName, targetFile, strlen(targetFile));
 
 // Load our list.
 fillList(sourceFile);
 
 pthread_t listenThread;
 pthread_create(&listenThread, NULL, (void *) prepareListener, NULL);
 
 sleep(1);
 
 prepareSender();
 
 printf("\nNo reply from %d IPs.\n", listSize - listChecked);
 printf("Finished.\n");
}

void fillList(const char *fileName) {
 FILE *read = fopen(fileName, "r");
 char line[256];
 while(fgets(line, sizeof(line), read) != NULL) {
  char wholeLine[256];
  memcpy(wholeLine, line, sizeof(line));
  
  char *ip = strtok(line, "\t ");
  
  addToList(ip, wholeLine);
 }
 
 fclose(read);
}

void addToList(char* ip, char *wholeLine) {
 struct listEntry *entry = (struct listEntry *) malloc(sizeof(struct listEntry));
 memcpy(entry->ip, ip, strlen(ip));
 memcpy(entry->wholeLine, wholeLine, strlen(wholeLine));
 entry->id = listSize; listSize++;
 entry->isChecked = 0;
 entry->next = NULL;
 
 if(listBegin == NULL) {
  listBegin = entry;
  listCur = entry;
 } else {
  listCur->next = entry;
  listCur = entry;
 }
}

void appendToFile(char *data) {
 FILE* write = fopen(targetFileName, "a+");
 fprintf(write, "%s", data);
 
 fclose(write);
}

void prepareListener() {
 // Create listener socket.
 int listenSock = socket(AF_INET, SOCK_DGRAM, 0);
 int option = 1; setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char *) &option, sizeof(option));
 
 if(listenSock < 0)
 {
  printf("Failed to create listener.\n");
 }
 
 // Bind to port.
 struct sockaddr_in addr;
 addr.sin_family = AF_INET;
 addr.sin_addr.s_addr = htonl(INADDR_ANY);
 addr.sin_port = htons(listenPort);
 
 if(bind(listenSock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
  printf("Failed to bind to port %d.\n", listenPort);
 }
 
 char buffer[4096];
 while(scanningActive) {
  //Clear receive buffer.
  memset(&buffer, 0, sizeof(buffer));
  
  // Wait for incoming packet.
  int addr_len = sizeof(addr);
  int recLen = recvfrom(listenSock, buffer, 8191, 0, (struct sockaddr *) &addr, &addr_len);
  const char *retIP = inet_ntoa(addr.sin_addr);
  
  // Put the data in our DNS header.
  struct dnshdr *dnsRec = (struct dnshdr *) &buffer;
  
  // Check if recursion is enabled.
  if(dnsRec->ra) {
   //Loop through our list and find the associated ip, then copy it to the new list.
   struct listEntry *entry = listBegin;
   
   while(1) {
    // Pick target IP.
    char targetIP[15];
    memcpy(targetIP, entry->ip, 15);
    
    if(strcmp(targetIP, retIP) == 0 && entry->isChecked == 0) {
     appendToFile(entry->wholeLine);
     
     entry->isChecked = 1;
     listChecked++;
    }
  
    if(entry->next != NULL) {
     entry = entry->next;
    } else {
     break;
    }
   }
   
   printf("\rIPs checked: %d/%d!      ", listChecked, listSize);
   fflush(stdout);
  }
 }
 
 close(listenSock);
}

void prepareSender() {
 // Prepare the socket.
 int sockFD = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
 
 if(sockFD == -1) {
  printf("You need to be root to use this tool!\n");
 }
 
 // Prepare holder.
 char packetPayload[256];
 int pointerPos = 0;
 
 // IP Header
 struct iphdr *iph = (struct iphdr*) &packetPayload[pointerPos]; pointerPos += sizeof(struct iphdr);
 iph->version = 4;
 iph->ihl = 5;
 iph->tos = 0;
 iph->id = 0;
 iph->frag_off = 0;
 iph->ttl = 128;
 iph->saddr = 0;
 iph->protocol = IPPROTO_UDP;
 iph->check = 0;
 
 // UDP Header
 struct udphdr *udph = (struct udphdr*) &packetPayload[pointerPos]; pointerPos += sizeof(struct udphdr);
 udph->source = htons(listenPort);
 udph->dest = htons(53);
 udph->check = 0;
 
 // Query Payload
 char payload[17] = "\x99\xd7\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x01";
 
 memcpy(&packetPayload[pointerPos], payload, sizeof(payload)); pointerPos += sizeof(payload);
 
 // Calculate the sizes
 udph->len = htons(sizeof(struct udphdr)) + htons(sizeof(payload));
 iph->tot_len = pointerPos;
 
 // Setup sock addr
 struct sockaddr_in addr;
 addr.sin_family = AF_INET;
 addr.sin_port = htons(53);
 
 // Loop through our list and send the dns queries.
 struct listEntry *entry = listBegin;
 
 while(1) {
  if(entry->isChecked == 0) {
   // Pick target IP.
   char targetIP[15];
   memcpy(targetIP, entry->ip, 15);
   
   // Setup sock address.
   addr.sin_addr.s_addr = inet_addr(targetIP);
  
   // Set target IP.
   iph->daddr = inet_addr(targetIP);
  
   // New checksums
   //udph->check = calculateUDPChecksum(iph, udph, payload, sizeof(payload));
   iph->check = csum((unsigned short *) &iph, sizeof(struct iphdr));
  
   // Send the packet.
   sendto(sockFD, packetPayload, iph->tot_len, 0, (struct sockaddr *) &addr, (size_t) sizeof(addr));
  
   usleep(1000000 / sendPPS);
  }
  
  if(entry->next != NULL) {
   entry = entry->next;
  } else {
   break;
  }
 }
 
 close(sockFD);
 
 sleep(2);
 
 scanningActive = 0;
}



unsigned short csum(unsigned short *ptr,int nbytes) {
 register long sum;
 unsigned short oddbyte;
 register short answer;

 sum=0;
 while(nbytes>1) {
  sum+=*ptr++;
  nbytes-=2;
 }
 if(nbytes==1) {
  oddbyte=0;
  *((u_char*)&oddbyte)=*(u_char*)ptr;
  sum+=oddbyte;
 }

 sum = (sum>>16)+(sum & 0xffff);
 sum = sum + (sum>>16);
 answer=(short)~sum;
 
 return(answer);
}

unsigned short calculateUDPChecksum(void *iphdr, struct udphdr *udphdr, char *payload, int payloadlen) {
    struct iphdr *v4hdr = (struct iphdr *)iphdr;
    unsigned long zero = 0;
    char pseudobuf[64]; memset(&pseudobuf, 0, sizeof(pseudobuf));
    char *ptr = pseudobuf;
    int chksumlen = 0;

    // Include the source and destination IP addresses
    memcpy(ptr, &v4hdr->saddr, sizeof(v4hdr->saddr));
    
    ptr += sizeof(v4hdr->saddr);
    chksumlen += sizeof(v4hdr->saddr);

    memcpy(ptr, &v4hdr->daddr, sizeof(v4hdr->daddr));
    
    ptr += sizeof(v4hdr->daddr);
    chksumlen += sizeof(v4hdr->daddr);
    
    // Include the 8 bit zero field
    memcpy(ptr, &zero, 1);
    
    ptr++;
    chksumlen += 1;

    // Protocol
    memcpy(ptr, &v4hdr->protocol, sizeof(v4hdr->protocol));
    
    ptr += sizeof(v4hdr->protocol);
    chksumlen += sizeof(v4hdr->protocol);

    // UDP length
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len));
    
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
    
    // UDP source port
    memcpy(ptr, &udphdr->source, sizeof(udphdr->source));
    
    ptr += sizeof(udphdr->source);
    chksumlen += sizeof(udphdr->source);

    // UDP destination port
    memcpy(ptr, &udphdr->dest, sizeof(udphdr->dest));
    
    ptr += sizeof(udphdr->dest);
    chksumlen += sizeof(udphdr->dest);

    // UDP length again
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len));
    
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
   
    // 16-bit UDP checksum, zero 
    memcpy(ptr, &zero, sizeof(unsigned short));
    
    ptr += sizeof(unsigned short);
    chksumlen += sizeof(unsigned short);
 
    // payload
    memcpy(ptr, payload, payloadlen);
    
    ptr += payloadlen;
    chksumlen += payloadlen;

    // pad to next 16-bit boundary
    if(payloadlen % 2 == 1) {
        *ptr = 0;
        
        ptr++;
        chksumlen++;
    }
 
    // Compute the checksum and put it in the UDP header
    return csum((unsigned short *) pseudobuf, chksumlen);
}